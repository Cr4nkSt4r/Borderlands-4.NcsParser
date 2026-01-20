/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#include "ncs_crc32.h"

namespace bl4::ncs {
namespace {
constexpr std::uint32_t poly = 0xEDB88320u;

static std::uint32_t table_entry(std::uint32_t i) {
    std::uint32_t crc = i;
    for (int bit = 0; bit < 8; bit++) {
        crc = (crc & 1u) != 0 ? (crc >> 1) ^ poly : (crc >> 1);
    }
    return crc;
}
}  // namespace

std::uint32_t crc32_iso(std::uint32_t seed, const std::uint8_t* data, std::size_t len) {
    std::uint32_t crc = seed;
    for (std::size_t i = 0; i < len; i++) {
        std::uint32_t idx = (crc ^ data[i]) & 0xFFu;
        crc = table_entry(idx) ^ (crc >> 8);
    }
    return crc;
}
}  // namespace bl4::ncs
