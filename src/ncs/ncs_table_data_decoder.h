/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#pragma once

#include "ncs_decomp.h"
#include "ncs_type_code_table.h"

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <json.hpp>

namespace bl4::ncs {

struct TableDataDecodeResult {
    nlohmann::ordered_json tables = nlohmann::ordered_json::object();
    nlohmann::ordered_json table_remaps = nlohmann::ordered_json::object();
    nlohmann::ordered_json record_tails = nlohmann::ordered_json::object();
    nlohmann::ordered_json record_tags = nlohmann::ordered_json::object();
    nlohmann::ordered_json type_flag_overrides = nlohmann::ordered_json::object();
    std::string data_tail_hex;
    std::optional<std::string> warning_or_error;
    std::vector<std::string> tag_failures;
};

struct TypeFlagStats {
    std::unordered_map<std::string, std::unordered_map<std::uint32_t, std::uint32_t>> leaf_flags;
    std::unordered_map<std::string, std::unordered_map<std::uint32_t, std::uint32_t>>
        leaf_value_flags;
    std::unordered_map<std::string, std::unordered_map<std::uint32_t, std::uint32_t>>
        leaf_parent_flags;
    std::unordered_map<std::string, std::unordered_map<std::uint32_t, std::uint32_t>> array_flags;
};

struct DecodeOptions {
    bool collect_table_remaps = true;
    bool collect_record_tails = true;
    bool collect_record_tags = true;
    bool collect_type_flag_overrides = true;
    bool collect_data_tail_hex = true;
    bool emit_all_type_flags = true;
    bool debug_progress = false;
};

TableDataDecodeResult decode_table_data(
    const TypeCodeTable& type_code_table,
    const DecompBlob& decomp,
    std::string_view file_label,
    TypeFlagStats* out_stats = nullptr,
    DecodeOptions options = {}
);

}  // namespace bl4::ncs
