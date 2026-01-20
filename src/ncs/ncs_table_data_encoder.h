/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#pragma once

#include "ncs_type_code_table.h"

#include <cstdint>
#include <string>
#include <vector>

#include <json.hpp>

namespace bl4::ncs {

struct TableDataEncodeResult {
    std::vector<std::uint8_t> data_section;
};

TableDataEncodeResult encode_table_data(
    const nlohmann::ordered_json& tables,
    const nlohmann::json& metadata,
    std::vector<std::string>& header_strings,
    std::vector<std::string>& value_strings,
    std::vector<std::string>& value_kinds,
    std::vector<std::string>& key_strings,
    const TypeCodeBodyHeader& type_header,
    std::uint32_t value_strings_declared_count,
    std::uint32_t value_kinds_declared_count,
    std::uint32_t key_strings_declared_count,
    bool allow_header_growth,
    bool allow_value_growth,
    bool allow_kind_growth,
    bool allow_key_growth
);

}  // namespace bl4::ncs
