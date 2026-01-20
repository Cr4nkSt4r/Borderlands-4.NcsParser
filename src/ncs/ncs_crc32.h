/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace bl4::ncs {
std::uint32_t crc32_iso(std::uint32_t seed, const std::uint8_t* data, std::size_t len);
inline std::uint32_t crc32_iso(const std::uint8_t* data, std::size_t len) {
    return crc32_iso(0xFFFFFFFFu, data, len) ^ 0xFFFFFFFFu;
}
}  // namespace bl4::ncs
