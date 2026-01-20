/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace bl4::ncs {

struct TypeCodeBodyHeader {
    std::uint8_t type_code_count = 0;
    std::string type_codes;
    std::uint16_t type_index_count = 0;
    int matrix_bit_count = 0;
    int matrix_byte_count = 0;
    std::vector<std::uint64_t> matrix_row_masks;
};

struct StringTable {
    std::uint32_t declared_count = 0;
    int raw_parsed_count = 0;
    int parsed_count = 0;
    std::uint32_t flags = 0;
    std::uint64_t byte_length = 0;
    std::vector<std::string> strings;
    std::size_t offset = 0;
};

struct TypeCodeTable {
    TypeCodeBodyHeader header{};
    std::vector<std::uint8_t> body;

    std::vector<std::string> value_strings;
    std::uint32_t value_strings_declared_count = 0;
    int value_strings_raw_parsed = 0;
    int value_strings_parsed = 0;
    std::uint32_t value_strings_flags = 0;
    std::uint64_t value_strings_byte_length = 0;

    std::vector<StringTable> tables;

    std::size_t data_offset = 0;

    std::span<const std::uint8_t> data_span() const;
};

std::optional<TypeCodeTable> try_parse_type_code_table(std::span<const std::uint8_t> body);

}  // namespace bl4::ncs
