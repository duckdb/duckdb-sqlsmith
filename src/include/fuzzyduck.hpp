//===----------------------------------------------------------------------===//
//                         DuckDB
//
// fuzzyduck.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb.hpp"
#include "duckdb/parser/query_node.hpp"
#include "random_nums_config.hpp"

namespace duckdb {

struct FileHandle;

class FuzzyDuck {
public:
	FuzzyDuck(ClientContext &context);
	~FuzzyDuck();

	ClientContext &context;
	uint32_t seed = 0;
	idx_t max_queries = 0;
	idx_t max_query_length = 0;
	string complete_log;
	string log;
	bool verbose_output = false;
	bool enable_verification = false;
	idx_t timeout = 30;
	string randoms_config_filepath;
	// RandomNumsConfig config;
	unordered_map<RandomPercentagesEnum, idx_t> config;

public:
	void Fuzz();
	void FuzzAllFunctions();

private:
	void BeginFuzzing();
	void EndFuzzing();

	string GenerateQuery(const idx_t &total_query_length);
	void RunQuery(string query);

	void LogMessage(const string &message);
	void LogTask(const string &message);
	void LogQuery(const string &message);

	void LogToCurrent(const string &message);
	void LogToComplete(const string &message);

	void TryRemoveFile(const string &path);

private:
	unique_ptr<FileHandle> complete_log_handle;
	unique_ptr<FileHandle> randoms_config_handle;
};

} // namespace duckdb
