/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#include "ncs/ncs_decomp_writer.h"

#include <cstring>
#include <stdexcept>

namespace bl4::ncs {
namespace {
void write_u16_le(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
}

void write_u32_le(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFu));
}

void write_u64_le(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 0; i < 8; i++) {
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu));
    }
}

std::vector<std::uint8_t> build_cstring_block(const std::vector<std::string>& strings) {
    std::size_t total = 0;
    for (const auto& s : strings) {
        total += s.size() + 1;
    }
    std::vector<std::uint8_t> out(total, 0);
    std::size_t pos = 0;
    for (const auto& s : strings) {
        if (!s.empty()) {
            std::memcpy(out.data() + pos, s.data(), s.size());
            pos += s.size();
        }
        if (pos >= out.size()) {
            throw std::runtime_error("Header string block overflow");
        }
        out[pos++] = 0;
    }
    return out;
}

void write_string_block(
    std::vector<std::uint8_t>& out,
    std::uint32_t count,
    std::uint32_t flags,
    const std::vector<std::string>& strings
) {
    if (strings.size() < count) {
        throw std::runtime_error("String block shorter than declared count");
    }
    std::vector<std::uint8_t> data;
    for (std::uint32_t i = 0; i < count; i++) {
        const auto& s = strings[static_cast<std::size_t>(i)];
        data.insert(data.end(), s.begin(), s.end());
        data.push_back(0);
    }

    write_u32_le(out, count);
    write_u32_le(out, flags);
    write_u64_le(out, static_cast<std::uint64_t>(data.size()));
    out.insert(out.end(), data.begin(), data.end());
}

std::vector<std::uint8_t> build_type_table_body(
    const TypeCodeBodyHeader& header,
    std::uint32_t value_strings_flags,
    std::uint32_t value_strings_declared_count,
    const std::vector<std::string>& value_strings,
    const std::vector<StringBlock>& string_tables,
    std::span<const std::uint8_t> data_section
) {
    if (header.type_codes.size() != header.type_code_count) {
        throw std::runtime_error("Type code count mismatch");
    }
    std::vector<std::uint8_t> out;
    out.push_back(header.type_code_count);
    write_u16_le(out, header.type_index_count);
    out.insert(out.end(), header.type_codes.begin(), header.type_codes.end());

    const int bit_count = header.type_index_count * header.type_code_count;
    const int byte_count = (bit_count + 7) / 8;
    std::vector<std::uint8_t> matrix(static_cast<std::size_t>(byte_count), 0);
    int bit_pos = 0;
    for (int row = 0; row < header.type_index_count; row++) {
        const std::uint64_t row_mask = header.matrix_row_masks[static_cast<std::size_t>(row)];
        for (int col = 0; col < header.type_code_count; col++) {
            if ((row_mask >> col) & 1ULL) {
                const int byte_pos = bit_pos >> 3;
                const int bit_in_byte = bit_pos & 7;
                matrix[static_cast<std::size_t>(byte_pos)] |=
                    static_cast<std::uint8_t>(1u << bit_in_byte);
            }
            bit_pos++;
        }
    }
    out.insert(out.end(), matrix.begin(), matrix.end());

    const std::uint32_t value_count = value_strings_declared_count > 0
                                          ? value_strings_declared_count
                                          : static_cast<std::uint32_t>(value_strings.size());
    write_string_block(out, value_count, value_strings_flags, value_strings);
    for (const auto& tbl : string_tables) {
        const std::uint32_t tbl_count = tbl.declared_count > 0
                                            ? tbl.declared_count
                                            : static_cast<std::uint32_t>(tbl.strings.size());
        write_string_block(out, tbl_count, tbl.flags, tbl.strings);
    }
    out.insert(out.end(), data_section.begin(), data_section.end());
    return out;
}
}  // namespace

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
) {
    std::vector<std::string> headers = header_strings;
    if (headers.empty()) {
        headers.emplace_back();
    }
    if (!headers.empty() && headers.front() != "") {
        headers.insert(headers.begin(), "");
    }

    const auto header_block = build_cstring_block(headers);
    const std::uint32_t entry_count = static_cast<std::uint32_t>(headers.size());
    const std::uint32_t string_bytes = static_cast<std::uint32_t>(header_block.size());

    const auto body = build_type_table_body(
        type_header, value_strings_flags, value_strings_declared_count, value_strings,
        string_tables, data_section
    );

    std::vector<std::uint8_t> out;
    out.reserve(16 + header_block.size() + body.size());
    write_u32_le(out, entry_count);
    write_u32_le(out, blob_flags);
    write_u32_le(out, string_bytes);
    write_u32_le(out, blob_reserved);
    out.insert(out.end(), header_block.begin(), header_block.end());
    out.insert(out.end(), body.begin(), body.end());
    const std::size_t mod = out.size() & 3u;
    if (mod != 0) {
        out.insert(out.end(), 4u - mod, 0);
    }
    return out;
}
}  // namespace bl4::ncs
