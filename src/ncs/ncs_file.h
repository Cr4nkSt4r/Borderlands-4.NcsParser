/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#pragma once

#include "oodle/oodle_api.h"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace bl4::ncs {
struct NcsHeader {
    std::uint32_t magic = 0;
    std::uint32_t flags = 0;
    std::uint32_t uncompressed_size = 0;
    std::uint32_t body_size = 0;

    std::uint8_t type_byte() const { return static_cast<std::uint8_t>(magic & 0xFFu); }
};

struct NcsBlockHeader {
    std::uint32_t magic_be = 0;
    std::uint32_t header_crc_be = 0;
    std::uint8_t codec = 0;
    std::uint8_t oodle_compressor_sel = 0;
    std::int8_t oodle_level = 0;
    std::uint8_t chunk_shift = 0;
    std::uint32_t chunk_count_be = 0;
    std::uint64_t uncompressed_total_be = 0;
    std::uint64_t compressed_total_be = 0;
    std::array<std::uint8_t, 32> header_tail32{};
};

struct NcsFile {
    NcsHeader file_header{};
    std::optional<NcsBlockHeader> block_header;
    std::vector<std::uint32_t> chunk_sizes;
    std::vector<std::uint8_t> decompressed_payload;
};

struct NcsBuildOptions {
    std::uint8_t type_byte = 1;
    std::uint32_t flags = 3;
    std::uint8_t codec = 3;
    std::uint8_t oodle_compressor_sel = 3;
    std::int8_t oodle_level = 8;
    std::uint8_t chunk_shift = 18;
    std::optional<std::array<std::uint8_t, 32>> header_tail32;
    OodleLZ_Compressor compressor = OodleLZ_Compressor::Kraken;
    OodleLZ_CompressionLevel level = OodleLZ_CompressionLevel::Optimal4;
};

NcsFile parse_ncs(std::span<const std::uint8_t> file_bytes, OodleApi* oodle);
std::vector<std::uint8_t> build_ncs_from_decomp(
    std::span<const std::uint8_t> payload,
    const NcsBuildOptions& opt,
    OodleApi* oodle
);
}  // namespace bl4::ncs
