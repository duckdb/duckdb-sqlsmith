#include "include/random_nums_config.hpp"

#include <algorithm>
#include <iterator>
#include <ctype.h>

namespace duckdb {

using namespace duckdb_yyjson;

unordered_map<RandomPercentagesEnum, idx_t> GetDefaultConfig() {
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

unordered_map<string, RandomPercentagesEnum> StringToRandomPercentagesEnum = {
    { "attach_percentage", RandomPercentagesEnum::ATTACH },
    { "attach_use_percentage", RandomPercentagesEnum::ATTACH_USE },
    { "delete_percentage", RandomPercentagesEnum::DELETE },
    { "detach_percentage", RandomPercentagesEnum::DETACH },
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
    { "result_modifiers", RandomPercentagesEnum::RESULT_MODIFIERS },
    { "limit_percent_modifier", RandomPercentagesEnum::LIMIT_PERCENT_MODIFIER },
    { "limit_percent_modifier_limit", RandomPercentagesEnum::LIMIT_PERCENT_MODIFIER_LIMIT },
    { "limit_percent_modifier_offset", RandomPercentagesEnum::LIMIT_PERCENT_MODIFIER_OFFSET },
    { "limit_modifier_limit", RandomPercentagesEnum::LIMIT_MODIFIER_LIMIT },
    { "limit_modifier_offset", RandomPercentagesEnum::LIMIT_MODIFIER_OFFSET }
};

enum Statements {
    select = 0,
    attach,
    delete_st,
    set,

};

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

unordered_map<RandomPercentagesEnum, idx_t> GetConfigFromFile(const char *json_string) {
    
    unordered_map<RandomPercentagesEnum, idx_t> config_from_file;
    auto doc = yyjson_read_file(json_string, YYJSON_READ_NOFLAG, NULL, NULL);
    if (doc) {
        yyjson_val *root = yyjson_doc_get_root(doc);
        if (yyjson_is_obj(root)) {
            ParseJsonObj(root, config_from_file);
        }
        // Free the doc
        yyjson_doc_free(doc);
    } else {
        // Couldn't read JSON with percentages config
        yyjson_doc_free(doc);
        return GetDefaultConfig();
    }
    return config_from_file;
}
} // namespace duckdb