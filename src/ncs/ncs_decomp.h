/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace bl4::ncs {
struct DecompHeader {
    std::uint32_t entry_count = 0;
    std::uint32_t flags = 0;
    std::uint32_t string_bytes = 0;
    std::uint32_t reserved = 0;
};

struct DecompBlob {
    DecompHeader header{};
    std::vector<std::string> strings;
    std::size_t body_offset = 0;
    std::vector<std::uint8_t> payload;

    std::span<const std::uint8_t> body_span() const;
};

DecompBlob parse_decomp(std::vector<std::uint8_t> payload);
}  // namespace bl4::ncs
