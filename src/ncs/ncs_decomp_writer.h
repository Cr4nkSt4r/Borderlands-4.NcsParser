/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#pragma once

#include "ncs_type_code_table.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace bl4::ncs {
struct StringBlock {
    std::uint32_t declared_count = 0;
    std::uint32_t flags = 0;
    std::vector<std::string> strings;
};

std::vector<std::uint8_t> build_decompressed_payload(
    std::uint32_t blob_flags,
    std::uint32_t blob_reserved,
    const std::vector<std::string>& header_strings,
    const TypeCodeBodyHeader& type_header,
    std::uint32_t value_strings_flags,
    std::uint32_t value_strings_declared_count,
    const std::vector<std::string>& value_strings,
    const std::vector<StringBlock>& string_tables,
    std::span<const std::uint8_t> data_section
);
}  // namespace bl4::ncs
