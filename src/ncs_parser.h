/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#pragma once

#include "json.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace bl4::ncs {

struct ParserDecodeOptions {
    std::optional<std::filesystem::path> oodle_path;
    bool collect_table_remaps = true;
    bool collect_record_tails = true;
    bool collect_record_tags = true;
    bool collect_type_flag_overrides = true;
    bool collect_data_tail_hex = true;
    bool emit_all_type_flags = true;
    bool keep_strings = false;
    bool debug = false;
};

struct DecodeResult {
    nlohmann::ordered_json tables = nlohmann::ordered_json::object();
    nlohmann::ordered_json metadata = nlohmann::ordered_json::object();
    std::vector<std::uint8_t> decomp_payload;
};

struct ParserEncodeOptions {
    std::optional<std::filesystem::path> oodle_path;
    bool debug = false;
};

struct EncodeResult {
    std::vector<std::uint8_t> decomp_payload;
    std::vector<std::uint8_t> ncs_bytes;
};

class NcsParser {
   public:
    static DecodeResult
    DecodeNcsFile(const std::filesystem::path& path, const ParserDecodeOptions& opt = {});
    static DecodeResult DecodeNcsBytes(
        std::span<const std::uint8_t> bytes,
        const ParserDecodeOptions& opt = {},
        std::string_view label = {}
    );
    static DecodeResult DecodeDecompBytes(
        std::span<const std::uint8_t> bytes,
        const ParserDecodeOptions& opt = {},
        std::string_view label = {}
    );

    static EncodeResult EncodeJsonToNcs(
        const nlohmann::ordered_json& tables,
        const nlohmann::json& metadata,
        const ParserEncodeOptions& opt = {},
        std::string_view label = {}
    );
};

}  // namespace bl4::ncs
