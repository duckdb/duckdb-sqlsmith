// ===----------------------------------------------------------------------===//
//                         DuckDB

// random_nums_config.hpp


// ===----------------------------------------------------------------------===//

#pragma once

#include "duckdb.hpp"
#include "yyjson.hpp"

namespace duckdb {

enum class RandomPercentagesEnum  : idx_t {
    // ----------------------------------
	// Generate Attach Percentages
	// ----------------------------------
    ATTACH = 0,
    ATTACH_USE = 1,
    ATTACH_READ_ONLY = 2,
    // ----------------------------------
	// Generate Detach Percentages
	// ----------------------------------
    DETACH = 3,
    DETACH_RANDOM_NAME = 4,
    // ----------------------------------
	// Generate Set Percentages
	// ----------------------------------
    SET = 5,
    SET_ATTACHED_DB = 6,
    // ----------------------------------
	// Generate Select Percentages
	// ----------------------------------
    DELETE = 7,

    // ----------------------------------
	// Generate Select Percentages
	// ----------------------------------
	SELECT = 8,
    SELECT_NODE = 9,
    SELECT_NODE_IS_DISTINCT = 10,
    SELECT_NODE_FROM_TABLE = 11,
    SELECT_NODE_WHERE = 12,
    SELECT_NODE_HAVING = 13,
    SELECT_NODE_GROUPS = 14,
    SELECT_NODE_GROUP_BY = 15,
    SELECT_NODE_QUALIFY = 16,
    SELECT_NODE_AGGREGATE = 17,
    SELECT_NODE_SAMPLE = 18,
    SELECT_NODE_SAMPLE_IS_PERC = 19,
    SELECT_NODE_SAMPLE_SIZE = 20,
    SETOP = 21,
    RESULT_MODIFIERS = 22,
    LIMIT_PERCENT_MODIFIER = 23,
    LIMIT_PERCENT_MODIFIER_LIMIT = 24,
    LIMIT_PERCENT_MODIFIER_OFFSET = 25,
    LIMIT_MODIFIER_LIMIT = 26,
    LIMIT_MODIFIER_OFFSET = 27,
    
    // ----------------------------------
	// Generate Create Percentages
	// ----------------------------------
    CREATE = 28,
    CREATE_GENERATE_SELECT = 29,
    CREATE_NUM_COLS = 30,
    // -----------------------------------
	// Generate Table Ref Percentages
	// -----------------------------------
    TABLE_REF_BASE_TABLE_REF_PERC = 31,
    TABLE_REF_EXPRESSION_LIST_REF = 32,
    TABLE_REF_JOIN_REF = 33,

    // -----------------------------------
	// Generate Join Ref Percentages
	// -----------------------------------
    JOIN_REF_CROSS = 34,
    JOIN_REF_ASOF = 35,
    JOIN_REF_NATURAL = 36,
    JOIN_REF_POSITIONAL = 37,
    JOIN_REF_GENERAL_EXPRESSION = 38,
    
    // -----------------------------------
	// Generate Expression Percentages
	// -----------------------------------
    EXPRESSION_COLUMN_REF = 39,
    EXPRESSION_CONSTANT = 40,
    EXPRESSION_SUBQUERY = 41,
    
    // -----------------------------------
	// Generate Constant Value Percentages
	// -----------------------------------
    CONSTANT_VALUE_BIGINT = 42,
    CONSTANT_VALUE_TO_STRING = 43,

    // -----------------------------------
	// Generate Function Percentages
	// -----------------------------------    
    FUNCTION_AGGREGATE_WINDOW_FUNCTION = 44,
    FUNCTION_AGGREGATE_ORDER_BY = 45,
    FUNCTION_AGGREGATE_FILTER = 60,
    FUNCTION_AGGREGATE_DISTINCT = 46,
    FUNCTION_AGGREGATE_RANDOM_EXPRESSION = 47,

    // -----------------------------------
	// Generate Window Function Percentages
	// -----------------------------------    
    WINDOW_FUNCTION_PARTITIONS = 48,
    WINDOW_FUNCTION_ORDERS = 49,
    WINDOW_FUNCTION_FILTER_EXPRESSION = 61,
    WINDOW_FUNCTION_IGNORE_NULLS = 50,
    WINDOW_FUNCTION_RESULT_OFFSET = 51,
    WINDOW_FUNCTION_RESULT_DEFAULT = 52,
    
    // -----------------------------------
	// Generate Star Percentages
	// -----------------------------------
    STAR_RELATION_NAME = 53,
    STAR_COLUMN_NAME = 54,
    STAR_COLUMN_NAME_EXCLUDE_LIST = 55,
    STAR_COLUMN_NAME_REPLACE_LIST = 62,
    STAR_COLUMNS_TRUE = 56,
    STAR_COLUMNS_TRUE_LAMBDA = 57,
    
    RELATIONAL_NAME_CHOOSE_CURRENT = 58,
    COLUMN_NAMES_CHOOSE_CURRENT = 59,
        
    COUNT

};

class RandomNumsConfig {
public: 
    RandomNumsConfig();
    RandomNumsConfig(const char *config_file_path);
    ~RandomNumsConfig();

    RandomPercentagesEnum percentages_selector;
    
    unordered_map<RandomPercentagesEnum, idx_t> GetDefaultConfig();
    unordered_map<RandomPercentagesEnum, idx_t> GetConfigFromFile(const char *json_string);
    string RandomPercentagesEnumToString(RandomPercentagesEnum type);

};

}// namespace duckdb