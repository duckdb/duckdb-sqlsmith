#include "fuzzyduck.hpp"
#include "duckdb/common/random_engine.hpp"
#include "statement_generator.hpp"
#include <algorithm>
#include <random>
#include <thread>

namespace duckdb {

FuzzyDuck::FuzzyDuck(ClientContext &context) : context(context) {
}

FuzzyDuck::~FuzzyDuck() {
}

void FuzzyDuck::BeginFuzzing() {
	auto &random_engine = RandomEngine::Get(context);
	if (seed == 0) {
		seed = random_engine.NextRandomInteger();
	}
	random_engine.SetSeed(seed);
	if (max_queries == 0) {
		throw InvalidInputException("Provide a max_queries argument greater than 0");
	}
	if (max_query_length == 0) {
		throw InvalidInputException("Provide a max_query_length argument greater than 0");
	}
	auto &fs = FileSystem::GetFileSystem(context);
	if (!complete_log.empty()) {
		TryRemoveFile(complete_log);
		complete_log_handle =
		    fs.OpenFile(complete_log, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
	}
	if (enable_verification) {
		RunQuery("PRAGMA enable_verification");
	}
	if (!randoms_config_filepath.empty()) {
		config = RandomNumsConfig().GetConfigFromFile(randoms_config_filepath.c_str());
	} else {
		config = RandomNumsConfig().GetDefaultConfig();
	}
}

void FuzzyDuck::EndFuzzing() {
	if (complete_log_handle) {
		complete_log_handle->Close();
	}
}

void FuzzyDuck::Fuzz() {
	idx_t total_query_length = 0;
	BeginFuzzing();
	LogTask("Generating queries with seed " + to_string(seed));
	for (idx_t i = 0; i < max_queries; i++) {
		LogMessage("Query " + to_string(i) + "\n");
		auto query = GenerateQuery(total_query_length);
		total_query_length += query.size() + 2; // add 2 for semicolon and newline
		if (total_query_length > max_query_length) {
			// break to prevent the query gets too large to process down-stream (e.g. should fit in issue tracker)
			LogTask("Max query length (" + to_string(max_query_length) + ") reached");
			break;
		}
		RunQuery(std::move(query));
	}
	EndFuzzing();
}

void FuzzyDuck::FuzzAllFunctions() {
	StatementGenerator generator(context);
	auto queries = generator.GenerateAllFunctionCalls();

	if (max_queries == 0) {
		max_queries = queries.size();
	}

	std::default_random_engine e(seed);
	std::shuffle(std::begin(queries), std::end(queries), e);
	idx_t total_query_length = 0;
	BeginFuzzing();
	for (auto &query : queries) {
		total_query_length += query.size() + 2; // add 2 for semicolon and newline
		if (total_query_length > max_query_length) {
			// break to prevent the query gets too large to process down-stream (e.g. should fit in issue tracker)
			LogTask("Max query length (" + to_string(max_query_length) + ") reached");
			break;
		}
		RunQuery(std::move(query));
	}
	EndFuzzing();
}

string FuzzyDuck::GenerateQuery(const idx_t &total_query_length) {
	// generate statement
	StatementGenerator generator(context);
	generator.verification_enabled = enable_verification;
	generator.config = config;
	// accumulate statement(s)
	auto statement = string("");
	if (generator.RandomPercentage(10)) {
		// multi statement
		idx_t number_of_statements = generator.RandomValue(30);
		idx_t length_multi_statement = 0;
		string statement_i;
		idx_t length_statement_to_add;
		LogTask("Generating Multi-Statement query of " + to_string(number_of_statements) + " statements");
		for (idx_t i = 0; i < number_of_statements; i++) {
			statement_i = generator.GenerateStatement()->ToString() + "; ";
			length_statement_to_add = statement_i.size();
			// break to prevent the query gets too large to process down-stream (e.g. should fit in issue tracker)
			if (total_query_length + length_multi_statement + length_statement_to_add > max_query_length) {
				break;
			}
			statement += statement_i;
			length_multi_statement += length_statement_to_add;
		}
	} else {
		// normal statement
		LogTask("Generating Single-Statement query");
		statement = generator.GenerateStatement()->ToString();
	}
	return statement;
}

void sleep_thread(Connection *con, atomic<bool> *is_active, atomic<bool> *timed_out, idx_t timeout_duration) {
	// timeout is given in seconds
	// we wait 10ms per iteration, so timeout * 100 gives us the amount of
	// iterations
	for (size_t i = 0; i < (size_t)(timeout_duration * 100) && *is_active; i++) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	if (*is_active) {
		*timed_out = true;
		con->Interrupt();
	}
}

void FuzzyDuck::RunQuery(string query) {
	LogQuery(query + ";");

	Connection con(*context.db);
	atomic<bool> is_active(true);
	atomic<bool> timed_out(false);
	std::thread interrupt_thread(sleep_thread, &con, &is_active, &timed_out, timeout);

	auto result = con.Query(query);
	is_active = false;
	interrupt_thread.join();
	if (timed_out) {
		LogMessage("TIMEOUT");
	} else if (result->HasError()) {
		LogMessage("EXECUTION ERROR: " + result->GetError());
	} else {
		LogMessage("EXECUTION SUCCESS!");
	}
}

void FuzzyDuck::TryRemoveFile(const string &path) {
	auto &fs = FileSystem::GetFileSystem(context);
	if (fs.FileExists(path)) {
		fs.RemoveFile(path);
	}
}

void FuzzyDuck::LogMessage(const string &message) {
	if (!verbose_output) {
		return;
	}
	Printer::Print(message);
}

void FuzzyDuck::LogTask(const string &message) {
	if (verbose_output) {
		LogMessage(message + "\n");
	}
	LogToCurrent(message);
}

void FuzzyDuck::LogQuery(const string &message) {
	if (verbose_output) {
		LogMessage(message + "\n");
	}
	LogToCurrent(message);
	LogToComplete(message);
}

void FuzzyDuck::LogToCurrent(const string &message) {
	if (log.empty()) {
		return;
	}
	auto &fs = FileSystem::GetFileSystem(context);
	TryRemoveFile(log);
	auto file = fs.OpenFile(log, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
	file->Write((void *)message.c_str(), message.size());
	file->Sync();
	file->Close();
}

void FuzzyDuck::LogToComplete(const string &message) {
	if (!complete_log_handle) {
		return;
	}
	complete_log_handle->Write((void *)message.c_str(), message.size());
	complete_log_handle->Write((void *)"\n", 1);
	complete_log_handle->Sync();
}

} // namespace duckdb
