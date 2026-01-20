/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#include "ncs_parser.h"

#include "ncs/ncs_decomp.h"
#include "ncs/ncs_decomp_writer.h"
#include "ncs/ncs_file.h"
#include "ncs/ncs_table_data_decoder.h"
#include "ncs/ncs_table_data_encoder.h"
#include "ncs/ncs_type_code_table.h"
#include "oodle/oodle_api.h"
#include "utils/fs_utils.h"
#include "utils/log.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <optional>
#include <stdexcept>

namespace bl4::ncs {

static std::string to_hex_u64(std::uint64_t v) {
    static const char hexdig[] = "0123456789ABCDEF";
    std::string out;
    out.resize(18);
    out[0] = '0';
    out[1] = 'x';
    for (int i = 0; i < 16; i++) {
        const int shift = 60 - (i * 4);
        out[2 + i] = hexdig[(v >> shift) & 0xFu];
    }
    return out;
}

static std::string to_hex_bytes(std::span<const std::uint8_t> bytes) {
    static const char hexdig[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(2 + bytes.size() * 2);
    out.push_back('0');
    out.push_back('x');
    for (const auto b : bytes) {
        out.push_back(hexdig[(b >> 4) & 0xFu]);
        out.push_back(hexdig[b & 0xFu]);
    }
    return out;
}

static std::string to_lower_ascii(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    for (unsigned char c : input) {
        if (c >= 'A' && c <= 'Z') {
            out.push_back(static_cast<char>(c + 32));
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

static std::uint32_t read_u32_json(const nlohmann::ordered_json& j, std::uint32_t def = 0);

static const std::array<std::pair<std::string_view, int>, 36> kEGbxTypeMap = {{
    {"None", 0},
    {"Bool", 1},
    {"Int", 2},
    {"Float", 3},
    {"Vector", 4},
    {"Rotator", 5},
    {"Object", 6},
    {"Actor", 7},
    {"String", 8},
    {"NavSpot", 9},
    {"Attribute", 0x0A},
    {"NumericRange", 0x0B},
    {"TargetInfo", 0x0C},
    {"GraphNodeOutput", 0x0D},
    {"SceneComponent", 0x0E},
    {"TrajectoryOptions", 0x0F},
    {"Waypoint", 0x10},
    {"GraphParam", 0x11},
    {"Name", 0x12},
    {"WorldStateRegistryActor", 0x13},
    {"Blackboard", 0x14},
    {"Double", 0x15},
    {"MissionAliasRef", 0x16},
    {"DataTable", 0x17},
    {"LinearColor", 0x18},
    {"HitResult", 0x19},
    {"ForceSelection", 0x1A},
    {"Text", 0x1B},
    {"Asset", 0x1C},
    {"GbxDef", 0x1D},
    {"WeightedAttributeInit", 0x1E},
    {"FactAddress", 0x1F},
    {"DialogEnumValue", 0x20},
    {"AttributeEvaluator", 0x21},
    {"GameplayTag", 0x22},
    {"MAX", 0x23},
}};

static std::optional<int> lookup_egbx_type(std::string_view name) {
    if (name.rfind("EGbxType::", 0) == 0) {
        name = name.substr(std::string_view("EGbxType::").size());
    }
    const std::string needle = to_lower_ascii(name);
    for (const auto& [k, v] : kEGbxTypeMap) {
        if (to_lower_ascii(k) == needle) {
            return v;
        }
    }
    return std::nullopt;
}

static std::optional<std::string_view> lookup_egbx_type_name(int value) {
    for (const auto& [k, v] : kEGbxTypeMap) {
        if (v == value) {
            return k;
        }
    }
    return std::nullopt;
}

static const nlohmann::ordered_json& unwrap_typeflags_node(const nlohmann::ordered_json& node) {
    if (node.is_object() && node.contains("__typeFlags") && node.contains("value")) {
        return node.at("value");
    }
    return node;
}

static void debug_validate_gbx_ue_data_table_types(const nlohmann::ordered_json& tables) {
    auto it = tables.find("gbx_ue_data_table");
    if (it == tables.end() || !it->is_object()) {
        return;
    }
    const auto& table = it.value();
    if (!table.contains("records") || !table.at("records").is_array()) {
        return;
    }

    int total = 0;
    int unknown = 0;
    for (const auto& rec : table.at("records")) {
        if (!rec.is_object() || !rec.contains("entries") || !rec.at("entries").is_array()) {
            continue;
        }
        for (const auto& entry : rec.at("entries")) {
            if (!entry.is_object()) {
                continue;
            }
            for (const auto& kv : entry.items()) {
                if (kv.key().rfind("__", 0) == 0) {
                    continue;
                }
                std::vector<const nlohmann::ordered_json*> stack;
                stack.push_back(&kv.value());
                while (!stack.empty()) {
                    const auto* cur = stack.back();
                    stack.pop_back();
                    if (cur->is_object()) {
                        auto rv_it = cur->find("row_value");
                        if (rv_it != cur->end()) {
                            const auto& rv = unwrap_typeflags_node(*rv_it);
                            if (rv.is_object() && rv.contains("type")) {
                                const auto& tv = rv.at("type");
                                total++;
                                if (tv.is_string()) {
                                    if (!lookup_egbx_type(tv.get<std::string>()).has_value()) {
                                        unknown++;
                                        BL4_LOG_INFO(
                                            "EGbxType unknown: %s (row_value)",
                                            tv.get<std::string>().c_str()
                                        );
                                    }
                                } else if (tv.is_number_integer() || tv.is_number_unsigned()) {
                                    const int v = static_cast<int>(read_u32_json(tv));
                                    if (!lookup_egbx_type_name(v).has_value()) {
                                        unknown++;
                                        BL4_LOG_INFO("EGbxType unknown numeric: %d (row_value)", v);
                                    }
                                }
                            }
                        }
                        for (const auto& inner : cur->items()) {
                            stack.push_back(&inner.value());
                        }
                    } else if (cur->is_array()) {
                        for (const auto& v : *cur) {
                            stack.push_back(&v);
                        }
                    }
                }
            }
        }
    }

    if (total > 0) {
        BL4_LOG_INFO(
            "EGbxType validation: table=gbx_ue_data_table total=%d unknown=%d", total, unknown
        );
    }
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

static std::uint64_t parse_hex_u64(std::string_view s) {
    std::uint64_t v = 0;
    std::size_t pos = 0;
    while (pos < s.size() && std::isspace(static_cast<unsigned char>(s[pos]))) {
        pos++;
    }
    if (pos + 1 < s.size() && s[pos] == '0' && (s[pos + 1] == 'x' || s[pos + 1] == 'X')) {
        pos += 2;
    }
    for (; pos < s.size(); pos++) {
        const char c = s[pos];
        if (std::isspace(static_cast<unsigned char>(c))) {
            continue;
        }
        const int n = hex_nibble(c);
        if (n < 0) {
            break;
        }
        v = (v << 4) | static_cast<std::uint64_t>(n);
    }
    return v;
}

static std::vector<std::uint8_t> parse_hex_bytes(std::string_view s) {
    std::vector<std::uint8_t> out;
    std::string clean;
    clean.reserve(s.size());
    for (char c : s) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean.push_back(c);
        }
    }
    std::size_t pos = 0;
    if (clean.rfind("0x", 0) == 0 || clean.rfind("0X", 0) == 0) {
        pos = 2;
    }
    const std::size_t hex_len = clean.size() - pos;
    if (hex_len == 0) {
        return out;
    }
    if ((hex_len & 1) != 0) {
        throw std::runtime_error("Invalid hex string length.");
    }
    out.reserve(hex_len / 2);
    for (std::size_t i = 0; i < hex_len; i += 2) {
        const int hi = hex_nibble(clean[pos + i]);
        const int lo = hex_nibble(clean[pos + i + 1]);
        if (hi < 0 || lo < 0) {
            throw std::runtime_error("Invalid hex string character.");
        }
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

static std::uint32_t read_u32_json(const nlohmann::ordered_json& j, std::uint32_t def) {
    if (j.is_number_unsigned()) {
        return j.get<std::uint32_t>();
    }
    if (j.is_number_integer()) {
        return static_cast<std::uint32_t>(j.get<std::int64_t>());
    }
    return def;
}

static std::unique_ptr<OodleApi> load_oodle(const ParserDecodeOptions& opt) {
    if (opt.oodle_path.has_value()) {
        return OodleApi::load(*opt.oodle_path);
    }
    return OodleApi::try_load_default();
}

static std::unique_ptr<OodleApi> load_oodle(const ParserEncodeOptions& opt) {
    if (opt.oodle_path.has_value()) {
        return OodleApi::load(*opt.oodle_path);
    }
    return OodleApi::try_load_default();
}

static void append_ncs_metadata(
    nlohmann::ordered_json& meta,
    const NcsFile& ncs,
    const std::optional<OodleLZ_Compressor> compressor
) {
    nlohmann::ordered_json ncs_meta = nlohmann::ordered_json::object();
    ncs_meta["typeByte"] = ncs.file_header.type_byte();
    ncs_meta["flags"] = ncs.file_header.flags;
    ncs_meta["uncompressedSize"] = ncs.file_header.uncompressed_size;
    ncs_meta["bodySize"] = ncs.file_header.body_size;

    if (ncs.block_header.has_value()) {
        const auto& bh = *ncs.block_header;
        ncs_meta["codec"] = bh.codec;
        ncs_meta["oodleSel"] = bh.oodle_compressor_sel;
        ncs_meta["oodleLevel"] = bh.oodle_level;
        ncs_meta["chunkShift"] = bh.chunk_shift;
        ncs_meta["headerTail32"] = to_hex_bytes(bh.header_tail32);
    } else {
        ncs_meta["codec"] = 0;
    }
    if (compressor.has_value()) {
        ncs_meta["oodleCompressor"] = static_cast<int>(*compressor);
    }
    meta["ncsHeader"] = std::move(ncs_meta);
}

static nlohmann::ordered_json build_metadata_block(
    const DecompBlob& decomp,
    const TypeCodeTable& type_table,
    nlohmann::ordered_json table_remaps,
    nlohmann::ordered_json record_tails,
    nlohmann::ordered_json record_tags,
    nlohmann::ordered_json type_flag_overrides,
    std::string data_tail_hex,
    bool keep_strings,
    const NcsFile* ncs,
    const std::optional<OodleLZ_Compressor> compressor
) {
    nlohmann::ordered_json meta = nlohmann::ordered_json::object();

    if (decomp.header.flags != 0) {
        meta["blobFlags"] = decomp.header.flags;
    }
    if (decomp.header.reserved != 0) {
        meta["blobReserved"] = decomp.header.reserved;
    }

    if (!type_table.header.type_codes.empty()) {
        nlohmann::ordered_json tch = nlohmann::ordered_json::object();
        tch["typeCodes"] = type_table.header.type_codes;
        tch["typeIndexCount"] = type_table.header.type_index_count;
        if (!type_table.header.matrix_row_masks.empty()) {
            nlohmann::ordered_json masks = nlohmann::ordered_json::array();
            for (const auto mask : type_table.header.matrix_row_masks) {
                masks.push_back(to_hex_u64(mask));
            }
            tch["matrixRowMasks"] = std::move(masks);
        }
        meta["typeCodeHeader"] = std::move(tch);
    }

    if (type_table.value_strings_flags != 0) {
        meta["valueStringsFlags"] = type_table.value_strings_flags;
    }
    if (type_table.value_strings_declared_count != 0) {
        meta["valueStringsDeclaredCount"] = type_table.value_strings_declared_count;
    }

    if (!type_table.tables.empty()) {
        nlohmann::ordered_json tables = nlohmann::ordered_json::array();
        for (const auto& tbl : type_table.tables) {
            nlohmann::ordered_json t = nlohmann::ordered_json::object();
            if (tbl.declared_count != 0) {
                t["declaredCount"] = tbl.declared_count;
            }
            t["flags"] = tbl.flags;
            t["strings"] = tbl.strings;
            tables.push_back(std::move(t));
        }
        meta["stringTables"] = std::move(tables);
    }

    if (table_remaps.is_object() && !table_remaps.empty()) {
        meta["tableRemaps"] = std::move(table_remaps);
    }
    if (record_tails.is_object() && !record_tails.empty()) {
        meta["recordTails"] = std::move(record_tails);
    }
    if (record_tags.is_object() && !record_tags.empty()) {
        meta["recordTags"] = std::move(record_tags);
    }
    if (type_flag_overrides.is_object() && !type_flag_overrides.empty()) {
        meta["typeFlagOverrides"] = std::move(type_flag_overrides);
    }
    if (ncs) {
        append_ncs_metadata(meta, *ncs, compressor);
    }

    return meta;
}

static DecodeResult decode_from_decomp(
    const DecompBlob& decomp,
    const ParserDecodeOptions& opt,
    std::string_view label,
    const NcsFile* ncs,
    const std::optional<OodleLZ_Compressor> compressor
) {
    auto type_table_opt = try_parse_type_code_table(decomp.body_span());
    if (!type_table_opt.has_value()) {
        throw std::runtime_error("No type-code table matched for " + std::string(label));
    }

    TableDataDecodeResult decoded = decode_table_data(
        *type_table_opt, decomp, label, nullptr,
        {opt.collect_table_remaps, opt.collect_record_tails, opt.collect_record_tags,
         opt.collect_type_flag_overrides, opt.collect_data_tail_hex, opt.emit_all_type_flags,
         opt.debug}
    );

    DecodeResult result{};
    result.tables = std::move(decoded.tables);
    if (opt.debug) {
        debug_validate_gbx_ue_data_table_types(result.tables);
    }
    result.metadata = build_metadata_block(
        decomp, *type_table_opt, std::move(decoded.table_remaps), std::move(decoded.record_tails),
        std::move(decoded.record_tags), std::move(decoded.type_flag_overrides),
        std::move(decoded.data_tail_hex), opt.keep_strings, ncs, compressor
    );
    result.decomp_payload = decomp.payload;
    return result;
}

DecodeResult
NcsParser::DecodeNcsFile(const std::filesystem::path& path, const ParserDecodeOptions& opt) {
    const auto bytes = bl4::fs_utils::read_file(path);
    if (bytes.empty()) {
        throw std::runtime_error("NCS file is empty: " + path.string());
    }
    return DecodeNcsBytes(bytes, opt, path.filename().string());
}

DecodeResult NcsParser::DecodeNcsBytes(
    std::span<const std::uint8_t> bytes,
    const ParserDecodeOptions& opt,
    std::string_view label
) {
    auto oodle = load_oodle(opt);
    const NcsFile ncs = parse_ncs(bytes, oodle.get());

    std::optional<OodleLZ_Compressor> compressor;
    if (oodle && ncs.block_header.has_value() && ncs.block_header->codec == 3
        && !ncs.chunk_sizes.empty()) {
        const int chunk_count = static_cast<int>(ncs.chunk_sizes.size());
        const std::size_t header_size = 64 + 4u * static_cast<std::size_t>(chunk_count);
        const std::size_t data_offset = 16 + header_size;
        if (data_offset < bytes.size()) {
            const std::size_t stored_len = ncs.chunk_sizes[0];
            if (data_offset + stored_len <= bytes.size()) {
                const int chunk_shift = ncs.block_header->chunk_shift;
                const std::size_t raw_len = std::min<std::size_t>(
                    ncs.file_header.uncompressed_size, static_cast<std::size_t>(1) << chunk_shift
                );
                const auto chunk_data = bytes.subspan(data_offset, stored_len);
                const auto comp = oodle->get_all_chunks_compressor(chunk_data, raw_len);
                if (comp != OodleLZ_Compressor::Invalid) {
                    compressor = comp;
                }
            }
        }
    }

    return decode_from_decomp(parse_decomp(ncs.decompressed_payload), opt, label, &ncs, compressor);
}

DecodeResult NcsParser::DecodeDecompBytes(
    std::span<const std::uint8_t> bytes,
    const ParserDecodeOptions& opt,
    std::string_view label
) {
    std::vector<std::uint8_t> payload(bytes.begin(), bytes.end());
    return decode_from_decomp(parse_decomp(std::move(payload)), opt, label, nullptr, std::nullopt);
}

static std::vector<std::string> read_string_array(const nlohmann::ordered_json& j) {
    std::vector<std::string> out;
    if (!j.is_array()) {
        return out;
    }
    out.reserve(j.size());
    for (const auto& v : j) {
        if (v.is_string()) {
            out.push_back(v.get<std::string>());
        }
    }
    return out;
}

static std::optional<OodleLZ_Compressor> parse_oodle_compressor(const nlohmann::ordered_json& j) {
    if (j.is_number_integer() || j.is_number_unsigned()) {
        const auto v = static_cast<int>(read_u32_json(j));
        switch (v) {
            case static_cast<int>(OodleLZ_Compressor::Kraken):
            case static_cast<int>(OodleLZ_Compressor::Mermaid):
            case static_cast<int>(OodleLZ_Compressor::Selkie):
            case static_cast<int>(OodleLZ_Compressor::Hydra):
            case static_cast<int>(OodleLZ_Compressor::Leviathan):
            case static_cast<int>(OodleLZ_Compressor::None):
                return static_cast<OodleLZ_Compressor>(v);
            default:
                break;
        }
    }
    if (j.is_string()) {
        const std::string s = j.get<std::string>();
        if (s == "Kraken") {
            return OodleLZ_Compressor::Kraken;
        }
        if (s == "Mermaid") {
            return OodleLZ_Compressor::Mermaid;
        }
        if (s == "Selkie") {
            return OodleLZ_Compressor::Selkie;
        }
        if (s == "Hydra") {
            return OodleLZ_Compressor::Hydra;
        }
        if (s == "Leviathan") {
            return OodleLZ_Compressor::Leviathan;
        }
        if (s == "None") {
            return OodleLZ_Compressor::None;
        }
    }
    return std::nullopt;
}

EncodeResult NcsParser::EncodeJsonToNcs(
    const nlohmann::ordered_json& tables,
    const nlohmann::json& metadata,
    const ParserEncodeOptions& opt,
    std::string_view label
) {
    const auto t0 = std::chrono::steady_clock::now();
    if (!tables.is_object()) {
        throw std::runtime_error("JSON root must be an object of tables for " + std::string(label));
    }
    if (!metadata.is_object()) {
        throw std::runtime_error("Missing metadata object for " + std::string(label));
    }

    const bool has_header_strings = metadata.contains("headerStrings")
                                    && metadata.at("headerStrings").is_array()
                                    && !metadata.at("headerStrings").empty();
    auto header_strings =
        read_string_array(metadata.value("headerStrings", nlohmann::ordered_json::array()));
    if (header_strings.empty()) {
        header_strings.push_back("");
    } else if (header_strings.front() != "") {
        header_strings.insert(header_strings.begin(), "");
    }
    const bool allow_header_growth = !has_header_strings;

    if (!metadata.contains("typeCodeHeader") || !metadata.at("typeCodeHeader").is_object()) {
        throw std::runtime_error("Missing typeCodeHeader in metadata for " + std::string(label));
    }
    const auto& tch_json = metadata.at("typeCodeHeader");
    const std::string type_codes =
        tch_json.contains("typeCodes") && tch_json.at("typeCodes").is_string()
            ? tch_json.at("typeCodes").get<std::string>()
            : std::string{};
    std::uint16_t type_index_count = 0;
    if (tch_json.contains("typeIndexCount")) {
        type_index_count = static_cast<std::uint16_t>(read_u32_json(tch_json.at("typeIndexCount")));
    }
    if (type_codes.empty() || type_index_count == 0) {
        throw std::runtime_error("Invalid typeCodeHeader in metadata for " + std::string(label));
    }

    TypeCodeBodyHeader type_header{};
    type_header.type_codes = type_codes;
    type_header.type_code_count = static_cast<std::uint8_t>(type_codes.size());
    type_header.type_index_count = type_index_count;
    if (tch_json.contains("matrixRowMasks") && tch_json.at("matrixRowMasks").is_array()) {
        for (const auto& v : tch_json.at("matrixRowMasks")) {
            if (v.is_string()) {
                type_header.matrix_row_masks.push_back(parse_hex_u64(v.get<std::string>()));
            } else if (v.is_number_unsigned() || v.is_number_integer()) {
                type_header.matrix_row_masks.push_back(
                    static_cast<std::uint64_t>(v.get<std::uint64_t>())
                );
            }
        }
    }
    if (type_header.matrix_row_masks.size() < type_header.type_index_count) {
        throw std::runtime_error("MatrixRowMasks length mismatch for " + std::string(label));
    }
    type_header.matrix_bit_count = type_header.type_index_count * type_header.type_code_count;
    type_header.matrix_byte_count = (type_header.matrix_bit_count + 7) / 8;

    std::uint32_t value_strings_flags = 0;
    std::uint32_t value_strings_declared_count = 0;
    if (metadata.contains("valueStringsFlags")) {
        value_strings_flags = read_u32_json(metadata.at("valueStringsFlags"));
    }
    if (metadata.contains("valueStringsDeclaredCount")) {
        value_strings_declared_count = read_u32_json(metadata.at("valueStringsDeclaredCount"));
    }

    std::vector<StringBlock> string_tables;
    if (metadata.contains("stringTables") && metadata.at("stringTables").is_array()) {
        for (const auto& t : metadata.at("stringTables")) {
            if (!t.is_object()) {
                continue;
            }
            StringBlock block{};
            if (t.contains("declaredCount")) {
                block.declared_count = read_u32_json(t.at("declaredCount"));
            }
            if (t.contains("flags")) {
                block.flags = read_u32_json(t.at("flags"));
            }
            if (t.contains("strings")) {
                block.strings = read_string_array(t.at("strings"));
            }
            if (block.declared_count == 0) {
                block.declared_count = static_cast<std::uint32_t>(block.strings.size());
            }
            if (block.strings.size() < block.declared_count) {
                block.strings.resize(block.declared_count);
            }
            string_tables.push_back(std::move(block));
        }
    }

    const bool has_value_strings = metadata.contains("valueStrings")
                                   && metadata.at("valueStrings").is_array()
                                   && !metadata.at("valueStrings").empty();
    auto value_strings =
        read_string_array(metadata.value("valueStrings", nlohmann::ordered_json::array()));
    const bool rebuild_value_strings = value_strings.empty();
    const bool allow_value_growth = !has_value_strings;
    if (value_strings_declared_count == 0) {
        value_strings_declared_count = static_cast<std::uint32_t>(value_strings.size());
    }
    if (!rebuild_value_strings && value_strings.size() < value_strings_declared_count) {
        value_strings.resize(value_strings_declared_count);
    }
    std::vector<std::string> value_kinds;
    std::vector<std::string> key_strings;
    if (!string_tables.empty()) {
        value_kinds = string_tables[0].strings;
    }
    if (string_tables.size() > 1) {
        key_strings = string_tables[1].strings;
    }
    const bool allow_kind_growth = value_kinds.empty();
    const bool allow_key_growth = key_strings.empty();

    std::uint32_t value_kinds_declared_count = 0;
    std::uint32_t key_strings_declared_count = 0;
    if (!string_tables.empty()) {
        value_kinds_declared_count = string_tables[0].declared_count;
        if (string_tables.size() > 1) {
            key_strings_declared_count = string_tables[1].declared_count;
        }
    }
    if (value_kinds_declared_count == 0) {
        value_kinds_declared_count = static_cast<std::uint32_t>(value_kinds.size());
    }
    if (key_strings_declared_count == 0) {
        key_strings_declared_count = static_cast<std::uint32_t>(key_strings.size());
    }

    auto encoded = encode_table_data(
        tables, metadata, header_strings, value_strings, value_kinds, key_strings, type_header,
        value_strings_declared_count, value_kinds_declared_count, key_strings_declared_count,
        allow_header_growth, allow_value_growth, allow_kind_growth, allow_key_growth
    );
    const auto t1 = std::chrono::steady_clock::now();

    if (allow_value_growth && value_strings_declared_count < value_strings.size()) {
        value_strings_declared_count = static_cast<std::uint32_t>(value_strings.size());
    }
    if (rebuild_value_strings && value_strings.size() < value_strings_declared_count) {
        value_strings.resize(value_strings_declared_count);
    }

    if (allow_kind_growth && value_kinds_declared_count < value_kinds.size()) {
        value_kinds_declared_count = static_cast<std::uint32_t>(value_kinds.size());
    }
    if (allow_key_growth && key_strings_declared_count < key_strings.size()) {
        key_strings_declared_count = static_cast<std::uint32_t>(key_strings.size());
    }

    if (string_tables.empty()) {
        if (!value_kinds.empty()) {
            StringBlock kinds{};
            kinds.flags = 0;
            kinds.declared_count = static_cast<std::uint32_t>(value_kinds.size());
            kinds.strings = value_kinds;
            string_tables.push_back(std::move(kinds));
        }
        if (!key_strings.empty()) {
            StringBlock keys{};
            keys.flags = 0;
            keys.declared_count = static_cast<std::uint32_t>(key_strings.size());
            keys.strings = key_strings;
            string_tables.push_back(std::move(keys));
        }
    } else {
        string_tables[0].strings = value_kinds;
        if (string_tables[0].declared_count == 0) {
            string_tables[0].declared_count =
                static_cast<std::uint32_t>(string_tables[0].strings.size());
        }
        if (string_tables[0].strings.size() < string_tables[0].declared_count) {
            string_tables[0].strings.resize(string_tables[0].declared_count);
        }
        if (string_tables.size() > 1) {
            string_tables[1].strings = key_strings;
            if (string_tables[1].declared_count == 0) {
                string_tables[1].declared_count =
                    static_cast<std::uint32_t>(string_tables[1].strings.size());
            }
            if (string_tables[1].strings.size() < string_tables[1].declared_count) {
                string_tables[1].strings.resize(string_tables[1].declared_count);
            }
        } else if (!key_strings.empty()) {
            StringBlock keys{};
            keys.flags = 0;
            keys.declared_count = static_cast<std::uint32_t>(key_strings.size());
            keys.strings = key_strings;
            string_tables.push_back(std::move(keys));
        }
    }

    std::uint32_t blob_flags = 0;
    std::uint32_t blob_reserved = 0;
    if (metadata.contains("blobFlags")) {
        blob_flags = read_u32_json(metadata.at("blobFlags"));
    }
    if (metadata.contains("blobReserved")) {
        blob_reserved = read_u32_json(metadata.at("blobReserved"));
    }

    auto decomp_payload = build_decompressed_payload(
        blob_flags, blob_reserved, header_strings, type_header, value_strings_flags,
        value_strings_declared_count, value_strings, string_tables, encoded.data_section
    );
    const auto t2 = std::chrono::steady_clock::now();

    NcsBuildOptions ncs_opt{};
    if (metadata.contains("ncsHeader") && metadata.at("ncsHeader").is_object()) {
        const auto& nh = metadata.at("ncsHeader");
        if (nh.contains("typeByte")) {
            ncs_opt.type_byte = static_cast<std::uint8_t>(read_u32_json(nh.at("typeByte")));
        }
        if (nh.contains("flags")) {
            ncs_opt.flags = read_u32_json(nh.at("flags"));
        }
        if (nh.contains("codec")) {
            ncs_opt.codec = static_cast<std::uint8_t>(read_u32_json(nh.at("codec")));
        }
        if (nh.contains("oodleSel")) {
            ncs_opt.oodle_compressor_sel =
                static_cast<std::uint8_t>(read_u32_json(nh.at("oodleSel")));
        }
        if (nh.contains("oodleLevel")) {
            ncs_opt.oodle_level = static_cast<std::int8_t>(read_u32_json(nh.at("oodleLevel")));
        }
        if (nh.contains("chunkShift")) {
            ncs_opt.chunk_shift = static_cast<std::uint8_t>(read_u32_json(nh.at("chunkShift")));
        }
        if (nh.contains("headerTail32") && nh.at("headerTail32").is_string()) {
            const auto bytes = parse_hex_bytes(nh.at("headerTail32").get<std::string>());
            if (bytes.size() == 32) {
                std::array<std::uint8_t, 32> tail{};
                std::copy(bytes.begin(), bytes.end(), tail.begin());
                ncs_opt.header_tail32 = tail;
            }
        }
        if (nh.contains("oodleCompressor")) {
            if (auto comp = parse_oodle_compressor(nh.at("oodleCompressor"))) {
                ncs_opt.compressor = *comp;
            }
        } else {
            const auto sel = static_cast<int>(ncs_opt.oodle_compressor_sel);
            switch (sel) {
                case static_cast<int>(OodleLZ_Compressor::Kraken):
                case static_cast<int>(OodleLZ_Compressor::Mermaid):
                case static_cast<int>(OodleLZ_Compressor::Selkie):
                case static_cast<int>(OodleLZ_Compressor::Hydra):
                case static_cast<int>(OodleLZ_Compressor::Leviathan):
                case static_cast<int>(OodleLZ_Compressor::None):
                    ncs_opt.compressor = static_cast<OodleLZ_Compressor>(sel);
                    break;
                default:
                    break;
            }
        }
        const int level = static_cast<int>(ncs_opt.oodle_level);
        if (level >= 0 && level <= 9) {
            ncs_opt.level = static_cast<OodleLZ_CompressionLevel>(level);
        }
    }

    auto oodle = load_oodle(opt);
    if (ncs_opt.flags != 0 && ncs_opt.codec == 3 && !oodle) {
        throw std::runtime_error("Oodle library not available for encoding " + std::string(label));
    }
    auto ncs_bytes = build_ncs_from_decomp(decomp_payload, ncs_opt, oodle.get());
    const auto t3 = std::chrono::steady_clock::now();

    EncodeResult result{};
    result.decomp_payload = std::move(decomp_payload);
    result.ncs_bytes = std::move(ncs_bytes);
    if (opt.debug) {
        const auto data_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        const auto decomp_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
        const auto ncs_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count();
        BL4_LOG_INFO(
            "Encode %s: data=%lldms decomp=%lldms ncs=%lldms", std::string(label).c_str(),
            static_cast<long long>(data_ms), static_cast<long long>(decomp_ms),
            static_cast<long long>(ncs_ms)
        );
    }
    return result;
}

}  // namespace bl4::ncs
