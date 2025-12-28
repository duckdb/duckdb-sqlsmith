#include "include/random_nums_config.hpp"

#include <algorithm>
#include <iterator>
#include <ctype.h>

namespace duckdb {

using namespace duckdb_yyjson;

unordered_map<string, RandomPercentagesEnum> StringToRandomPercentagesEnum = {
	{ "attach_percentage", RandomPercentagesEnum::ATTACH },
	{ "attach_use_percentage", RandomPercentagesEnum::ATTACH_USE },
	{ "attach_read_only", RandomPercentagesEnum::ATTACH_READ_ONLY },
	{ "detach_percentage", RandomPercentagesEnum::DETACH },
	{ "detach_random_name", RandomPercentagesEnum::DETACH_RANDOM_NAME },
	{ "set_percentage", RandomPercentagesEnum::SET },
	{ "set_attached_db", RandomPercentagesEnum::SET_ATTACHED_DB },
	{ "delete_percentage", RandomPercentagesEnum::DELETE },
	{ "select_percentage", RandomPercentagesEnum::SELECT },
	{ "select_node_perc", RandomPercentagesEnum::SELECT_NODE },
	{ "select_node_is_distinct_perc", RandomPercentagesEnum::SELECT_NODE_IS_DISTINCT },
	{ "select_node_from_table_perc", RandomPercentagesEnum::SELECT_NODE_FROM_TABLE },
	{ "select_node_where_perc", RandomPercentagesEnum::SELECT_NODE_WHERE },
	{ "select_node_having_perc", RandomPercentagesEnum::SELECT_NODE_HAVING },
	{ "select_node_groups_perc", RandomPercentagesEnum::SELECT_NODE_GROUPS },
	{ "select_node_group_by_perc", RandomPercentagesEnum::SELECT_NODE_GROUP_BY },
	{ "select_node_qualify_perc", RandomPercentagesEnum::SELECT_NODE_QUALIFY },
	{ "select_node_aggregate_perc", RandomPercentagesEnum::SELECT_NODE_AGGREGATE },
	{ "select_node_sample_perc", RandomPercentagesEnum::SELECT_NODE_SAMPLE },
	{ "select_node_sample_is_perc", RandomPercentagesEnum::SELECT_NODE_SAMPLE_IS_PERC },
	{ "select_node_sample_size", RandomPercentagesEnum::SELECT_NODE_SAMPLE_SIZE },
	{ "setop", RandomPercentagesEnum::SETOP },
	{ "result_modifiers", RandomPercentagesEnum::RESULT_MODIFIERS },
	{ "limit_percent_modifier", RandomPercentagesEnum::LIMIT_PERCENT_MODIFIER },
	{ "limit_percent_modifier_limit", RandomPercentagesEnum::LIMIT_PERCENT_MODIFIER_LIMIT },
	{ "limit_percent_modifier_offset", RandomPercentagesEnum::LIMIT_PERCENT_MODIFIER_OFFSET },
	{ "limit_modifier_limit", RandomPercentagesEnum::LIMIT_MODIFIER_LIMIT },
	{ "limit_modifier_offset", RandomPercentagesEnum::LIMIT_MODIFIER_OFFSET },
	{ "create_percentage", RandomPercentagesEnum::CREATE },
	{ "create_generate_select", RandomPercentagesEnum::CREATE_GENERATE_SELECT },
	{ "create_num_cols", RandomPercentagesEnum::CREATE_NUM_COLS },
	{ "table_ref_base_table_ref_perc", RandomPercentagesEnum::TABLE_REF_BASE_TABLE_REF_PERC },
	{ "table_ref_expression_list_ref", RandomPercentagesEnum::TABLE_REF_EXPRESSION_LIST_REF },
	{ "table_ref_join_ref", RandomPercentagesEnum::TABLE_REF_JOIN_REF },
	{ "join_ref_cross", RandomPercentagesEnum::JOIN_REF_CROSS },
	{ "join_ref_asof", RandomPercentagesEnum::JOIN_REF_ASOF },
	{ "join_ref_natural", RandomPercentagesEnum::JOIN_REF_NATURAL },
	{ "join_ref_positional", RandomPercentagesEnum::JOIN_REF_POSITIONAL },
	{ "join_ref_general_expression", RandomPercentagesEnum::JOIN_REF_GENERAL_EXPRESSION },
	{ "expression_column_ref", RandomPercentagesEnum::EXPRESSION_COLUMN_REF },
	{ "expression_constant", RandomPercentagesEnum::EXPRESSION_CONSTANT },
	{ "expression_subquery", RandomPercentagesEnum::EXPRESSION_SUBQUERY },
	{ "constant_value_bigint", RandomPercentagesEnum::CONSTANT_VALUE_BIGINT },
	{ "constant_value_to_string", RandomPercentagesEnum::CONSTANT_VALUE_TO_STRING },
	{ "function_aggregate_window_function", RandomPercentagesEnum::FUNCTION_AGGREGATE_WINDOW_FUNCTION },
	{ "function_aggregate_order_by", RandomPercentagesEnum::FUNCTION_AGGREGATE_ORDER_BY },
	{ "function_aggregate_filter", RandomPercentagesEnum::FUNCTION_AGGREGATE_FILTER },
	{ "function_aggregate_random_expression", RandomPercentagesEnum::FUNCTION_AGGREGATE_RANDOM_EXPRESSION },
	{ "function_aggregate_distinct", RandomPercentagesEnum::FUNCTION_AGGREGATE_DISTINCT },
	{ "window_function_partitions", RandomPercentagesEnum::WINDOW_FUNCTION_PARTITIONS },
	{ "window_function_filter_expr", RandomPercentagesEnum::WINDOW_FUNCTION_FILTER_EXPRESSION },
	{ "window_function_orders", RandomPercentagesEnum::WINDOW_FUNCTION_ORDERS },
	{ "window_function_ignore_nulls", RandomPercentagesEnum::WINDOW_FUNCTION_IGNORE_NULLS },
	{ "window_function_result_offset", RandomPercentagesEnum::WINDOW_FUNCTION_RESULT_OFFSET },
	{ "window_function_result_default", RandomPercentagesEnum::WINDOW_FUNCTION_RESULT_DEFAULT },
	{ "star_relation_name", RandomPercentagesEnum::STAR_RELATION_NAME },
	{ "star_column_name_exclude_list", RandomPercentagesEnum::STAR_COLUMN_NAME_EXCLUDE_LIST },
	{ "star_column_name_replace_list", RandomPercentagesEnum::STAR_COLUMN_NAME_REPLACE_LIST },
	{ "star_column_name", RandomPercentagesEnum::STAR_COLUMN_NAME },
	{ "star_columns_true", RandomPercentagesEnum::STAR_COLUMNS_TRUE },
	{ "star_columns_true_lambda", RandomPercentagesEnum::STAR_COLUMNS_TRUE_LAMBDA },
	{ "relational_name_choose_current", RandomPercentagesEnum::RELATIONAL_NAME_CHOOSE_CURRENT },
	{ "column_names_choose_current", RandomPercentagesEnum::COLUMN_NAMES_CHOOSE_CURRENT }
};

RandomNumsConfig::RandomNumsConfig() {
	GetDefaultConfig();
}

RandomNumsConfig::RandomNumsConfig(const char *config_file_path) {
	GetConfigFromFile(config_file_path);
}

RandomNumsConfig::~RandomNumsConfig() {
}

unordered_map<RandomPercentagesEnum, idx_t> RandomNumsConfig::GetDefaultConfig() {
	unordered_map<RandomPercentagesEnum, idx_t> default_config = {
		{ RandomPercentagesEnum::ATTACH, 40 },
		{ RandomPercentagesEnum::ATTACH_USE, 50 },
		{ RandomPercentagesEnum::DELETE, 40 },
		{ RandomPercentagesEnum::DETACH, 60 },
		{ RandomPercentagesEnum::SELECT, 60 },
		{ RandomPercentagesEnum::SET, 30 }
	};
	return default_config;
}

void ParseJsonObj(yyjson_val *obj, unordered_map<RandomPercentagesEnum, idx_t> &config_from_file) {
	yyjson_obj_iter iter;
	yyjson_obj_iter_init(obj, &iter);
	size_t idx, max;
	yyjson_val *key, *val;
	yyjson_obj_foreach(obj, idx, max, key, val) {
		const char* root_key = yyjson_get_str(key);
		auto it = StringToRandomPercentagesEnum.find(root_key);
		if (it != StringToRandomPercentagesEnum.end()) {
			RandomPercentagesEnum perc_type = it->second;
			auto perc_value = yyjson_get_str(val);
			if (perc_value) {
				config_from_file[perc_type] = std::stoi(perc_value);
			}
		}
		if (yyjson_is_obj(val)) {
			ParseJsonObj(val, config_from_file);
		}
	}
}

unordered_map<RandomPercentagesEnum, idx_t> RandomNumsConfig::GetConfigFromFile(const char *json_string) {
	
	unordered_map<RandomPercentagesEnum, idx_t> config_from_file;
	auto doc = yyjson_read_file(json_string, YYJSON_READ_NOFLAG, NULL, NULL);
	if (doc) {
		yyjson_val *root = yyjson_doc_get_root(doc);
		if (yyjson_is_obj(root)) {
			ParseJsonObj(root, config_from_file);
		}
		yyjson_doc_free(doc);
	} else {
		// Couldn't read JSON with percentages config
		yyjson_doc_free(doc);
		return GetDefaultConfig();
	}
	// set values of missing statement types to 0
	for (idx_t i = 0; i < static_cast<int>(RandomPercentagesEnum::COUNT); ++i) {
		RandomPercentagesEnum statement_type = static_cast<RandomPercentagesEnum>(i);
		if (config_from_file.find(statement_type) == config_from_file.end()) {
			config_from_file[statement_type] = 0;
		}
	}
	return config_from_file;
	}
} // namespace duckdb