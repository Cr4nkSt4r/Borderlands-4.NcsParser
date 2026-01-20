/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#include "ncs/ncs_decomp.h"

#include <limits>
#include <stdexcept>

namespace bl4::ncs {
static std::uint32_t read_u32_le(const std::vector<std::uint8_t>& buf, std::size_t off) {
    if (off + 4 > buf.size()) {
        throw std::runtime_error(std::string("read_u32_le out of bounds"));
    }
    return (std::uint32_t)buf[off] | ((std::uint32_t)buf[off + 1] << 8)
           | ((std::uint32_t)buf[off + 2] << 16) | ((std::uint32_t)buf[off + 3] << 24);
}

std::span<const std::uint8_t> DecompBlob::body_span() const {
    if (body_offset >= payload.size()) {
        return {};
    }
    return std::span<const std::uint8_t>(
        payload.data() + body_offset, payload.size() - body_offset
    );
}

DecompBlob parse_decomp(std::vector<std::uint8_t> payload) {
    if (payload.size() < 16) {
        throw std::runtime_error(
            std::string("NCS decompressed payload too small for .decomp header.")
        );
    }

    DecompHeader hdr{};
    hdr.entry_count = read_u32_le(payload, 0);
    hdr.flags = read_u32_le(payload, 4);
    hdr.string_bytes = read_u32_le(payload, 8);
    hdr.reserved = read_u32_le(payload, 12);

    const std::size_t string_block_start = 16;
    const std::size_t string_block_end =
        std::min(payload.size(), string_block_start + static_cast<std::size_t>(hdr.string_bytes));

    if (hdr.entry_count > static_cast<std::uint32_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error(std::string("Unrealistic .decomp entryCount."));
    }

    std::vector<std::string> strings;
    strings.reserve(static_cast<std::size_t>(hdr.entry_count));
    std::size_t pos = string_block_start;
    for (std::size_t i = 0; i < hdr.entry_count; i++) {
        if (pos > string_block_end) {
            throw std::runtime_error(std::string("String block truncated."));
        }

        const std::size_t start = pos;
        while (pos < string_block_end && payload[pos] != 0) {
            pos++;
        }

        strings.emplace_back(reinterpret_cast<const char*>(payload.data() + start), pos - start);
        if (pos < string_block_end) {
            pos++;  // skip terminator
        }
    }

    DecompBlob out{};
    out.header = hdr;
    out.strings = std::move(strings);
    out.body_offset = string_block_end;
    out.payload = std::move(payload);
    return out;
}
}  // namespace bl4::ncs
