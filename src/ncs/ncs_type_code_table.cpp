/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#include "ncs/ncs_type_code_table.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace bl4::ncs {
namespace {
static std::uint16_t read_u16_le(const std::vector<std::uint8_t>& buf, std::size_t off) {
    if (off + 2 > buf.size()) {
        throw std::runtime_error(std::string("read_u16_le out of bounds"));
    }
    return static_cast<std::uint16_t>(buf[off] | (static_cast<std::uint16_t>(buf[off + 1]) << 8));
}

static std::uint32_t read_u32_le(const std::vector<std::uint8_t>& buf, std::size_t off) {
    if (off + 4 > buf.size()) {
        throw std::runtime_error(std::string("read_u32_le out of bounds"));
    }
    return (std::uint32_t)buf[off] | ((std::uint32_t)buf[off + 1] << 8)
           | ((std::uint32_t)buf[off + 2] << 16) | ((std::uint32_t)buf[off + 3] << 24);
}

static std::uint64_t read_u64_le(const std::vector<std::uint8_t>& buf, std::size_t off) {
    if (off + 8 > buf.size()) {
        throw std::runtime_error(std::string("read_u64_le out of bounds"));
    }
    std::uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= (std::uint64_t)buf[off + i] << (8 * i);
    }
    return v;
}

static bool read_bit(const std::vector<std::uint8_t>& buf, std::size_t bit_pos) {
    const std::size_t byte_pos = bit_pos >> 3;
    const std::size_t bit_in_byte = bit_pos & 7;
    if (byte_pos >= buf.size()) {
        throw std::runtime_error(std::string("Unexpected EOF while reading bit-matrix."));
    }
    return ((buf[byte_pos] >> bit_in_byte) & 1u) != 0;
}

static std::vector<std::string> parse_null_terminated_strings(std::span<const std::uint8_t> block) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (pos < block.size()) {
        const std::size_t start = pos;
        while (pos < block.size() && block[pos] != 0) {
            pos++;
        }
        out.emplace_back(reinterpret_cast<const char*>(block.data() + start), pos - start);
        if (pos >= block.size()) {
            break;
        }
        pos++;  // skip terminator
    }
    return out;
}

static void
try_repair_merged_numeric_prefix_strings(std::vector<std::string>& strings, int target_count) {
    for (int guard = 0; guard < 64 && static_cast<int>(strings.size()) < target_count; guard++) {
        int candidate = -1;
        int split_pos = -1;

        for (int i = 0; i < static_cast<int>(strings.size()); i++) {
            const auto& s = strings[i];
            if (s.empty()) {
                continue;
            }
            int p = 0;
            while (p < static_cast<int>(s.size())
                   && std::isdigit(static_cast<unsigned char>(s[p]))) {
                p++;
            }
            if (p < 2 || p >= static_cast<int>(s.size())) {
                continue;
            }
            if (!std::isalpha(static_cast<unsigned char>(s[p]))) {
                continue;
            }
            candidate = i;
            split_pos = p;
            break;
        }

        if (candidate < 0 || split_pos < 0) {
            break;
        }

        const std::string s0 = strings[static_cast<std::size_t>(candidate)];
        const std::string left = s0.substr(0, static_cast<std::size_t>(split_pos));
        const std::string right = s0.substr(static_cast<std::size_t>(split_pos));
        strings[static_cast<std::size_t>(candidate)] = left;
        strings.insert(strings.begin() + candidate + 1, right);
    }
}

static std::optional<StringTable>
read_string_block_or_null(const std::vector<std::uint8_t>& buf, std::size_t pos) {
    if (pos + 16 > buf.size()) {
        return std::nullopt;
    }

    const std::uint32_t declared_count = read_u32_le(buf, pos + 0);
    const std::uint32_t flags = read_u32_le(buf, pos + 4);
    const std::uint64_t byte_len = read_u64_le(buf, pos + 8);
    if (byte_len > (buf.size() - (pos + 16))) {
        return std::nullopt;
    }

    const std::size_t byte_len_int = static_cast<std::size_t>(byte_len);
    const std::size_t data_start = pos + 16;
    auto strings = parse_null_terminated_strings(
        std::span<const std::uint8_t>(buf.data() + data_start, byte_len_int)
    );
    const int raw_parsed = static_cast<int>(strings.size());
    int parsed = raw_parsed;

    if (declared_count <= static_cast<std::uint32_t>(std::numeric_limits<int>::max())) {
        const int target = static_cast<int>(declared_count);
        if (static_cast<int>(strings.size()) < target) {
            try_repair_merged_numeric_prefix_strings(strings, target);
            parsed = static_cast<int>(strings.size());
        }

        if (parsed > target) {
            parsed = target;
        }

        if (static_cast<int>(strings.size()) > target) {
            strings.resize(static_cast<std::size_t>(target));
        }
        while (static_cast<int>(strings.size()) < target) {
            strings.emplace_back();
        }
    }

    StringTable out{};
    out.declared_count = declared_count;
    out.raw_parsed_count = raw_parsed;
    out.parsed_count = parsed;
    out.flags = flags;
    out.byte_length = byte_len;
    out.strings = std::move(strings);
    out.offset = pos;
    return out;
}

static StringTable read_string_block(const std::vector<std::uint8_t>& buf, std::size_t& pos) {
    auto blk = read_string_block_or_null(buf, pos);
    if (!blk.has_value()) {
        throw std::runtime_error(std::string("Missing string block."));
    }
    const auto next_pos = blk->offset + 16 + static_cast<std::size_t>(blk->byte_length);
    pos = next_pos;
    return *blk;
}
}  // namespace

std::span<const std::uint8_t> TypeCodeTable::data_span() const {
    if (data_offset >= body.size()) {
        return {};
    }
    return std::span<const std::uint8_t>(body.data() + data_offset, body.size() - data_offset);
}

std::optional<TypeCodeTable> try_parse_type_code_table(std::span<const std::uint8_t> body_span) {
    if (body_span.empty()) {
        return std::nullopt;
    }

    try {
        TypeCodeTable out{};
        out.body.assign(body_span.begin(), body_span.end());
        if (out.body.size() < 3) {
            throw std::runtime_error(
                std::string("NCS .decomp body too small for TypeCodeTable header.")
            );
        }

        std::size_t pos = 0;
        const std::uint8_t type_code_count = out.body[pos++];
        const std::uint16_t type_index_count = read_u16_le(out.body, pos);
        pos += 2;
        if (type_code_count == 0 || type_code_count > 64) {
            throw std::runtime_error(std::string("Suspicious TypeCodeCount."));
        }

        if (pos + type_code_count > out.body.size()) {
            throw std::runtime_error(std::string("TypeCodes runs past end of body."));
        }

        const std::string type_codes(
            reinterpret_cast<const char*>(out.body.data() + pos),
            static_cast<std::size_t>(type_code_count)
        );
        pos += type_code_count;

        const int matrix_bit_count =
            static_cast<int>(type_code_count) * static_cast<int>(type_index_count);
        const int matrix_byte_count = (matrix_bit_count + 7) / 8;

        std::size_t bit_pos = pos * 8;
        if (pos + static_cast<std::size_t>(matrix_byte_count) + 16 > out.body.size()) {
            throw std::runtime_error(std::string("Bit-matrix runs past end of body."));
        }

        std::vector<std::uint64_t> row_masks;
        row_masks.reserve(type_index_count);
        for (int row = 0; row < type_index_count; row++) {
            std::uint64_t mask = 0;
            for (int col = 0; col < type_code_count; col++) {
                if (read_bit(out.body, bit_pos++)) {
                    mask |= 1ULL << col;
                }
            }
            row_masks.push_back(mask);
        }

        if ((bit_pos & 7) != 0) {
            bit_pos += 8 - (bit_pos & 7);
        }
        pos = bit_pos / 8;

        const auto value_block = read_string_block(out.body, pos);
        out.value_strings = value_block.strings;
        out.value_strings_declared_count = value_block.declared_count;
        out.value_strings_raw_parsed = value_block.raw_parsed_count;
        out.value_strings_parsed = value_block.parsed_count;
        out.value_strings_flags = value_block.flags;
        out.value_strings_byte_length = value_block.byte_length;

        std::vector<StringTable> tables;
        while (pos + 16 <= out.body.size()) {
            auto next = read_string_block_or_null(out.body, pos);
            if (!next.has_value()) {
                break;
            }
            if (next->parsed_count != static_cast<int>(next->declared_count)) {
                break;
            }
            tables.push_back(*next);
            pos = next->offset + 16 + static_cast<std::size_t>(next->byte_length);
        }

        TypeCodeBodyHeader hdr{};
        hdr.type_code_count = type_code_count;
        hdr.type_codes = type_codes;
        hdr.type_index_count = type_index_count;
        hdr.matrix_bit_count = matrix_bit_count;
        hdr.matrix_byte_count = matrix_byte_count;
        hdr.matrix_row_masks = row_masks;

        out.header = std::move(hdr);
        out.tables = std::move(tables);
        out.data_offset = pos;
        return out;
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace bl4::ncs
