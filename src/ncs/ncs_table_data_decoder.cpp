/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#include "ncs_table_data_decoder.h"
#include "ncs_bit_reader.h"
#include "utils/log.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <unordered_set>

namespace bl4::ncs {
static std::string bytes_to_hex(std::span<const std::uint8_t> bytes) {
    static const char hexdig[] = "0123456789ABCDEF";
    std::string out;
    out.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); i++) {
        const std::uint8_t b = bytes[i];
        out[i * 2] = hexdig[(b >> 4) & 0xF];
        out[i * 2 + 1] = hexdig[b & 0xF];
    }
    return out;
}

static std::vector<std::uint8_t> read_bits_to_packed_bytes(BitReader& br, int bit_count) {
    if (bit_count <= 0) {
        return {};
    }
    std::vector<std::uint8_t> out(static_cast<std::size_t>((bit_count + 7) / 8), 0);
    int out_bit = 0;
    int remaining = bit_count;
    while (remaining > 0) {
        const int chunk = remaining > 32 ? 32 : remaining;
        const std::uint32_t v = br.read_bits(chunk);
        for (int i = 0; i < chunk; i++) {
            if (((v >> i) & 1u) != 0) {
                const int bit_pos = out_bit + i;
                out[static_cast<std::size_t>(bit_pos >> 3)] |=
                    static_cast<std::uint8_t>(1u << (bit_pos & 7));
            }
        }
        out_bit += chunk;
        remaining -= chunk;
    }
    return out;
}

int index_bits(int count) {
    if (count <= 1) {
        return 1;
    }
    int v = count - 1;
    int bits = 0;
    while (v > 0) {
        bits++;
        v >>= 1;
    }
    return bits == 0 ? 1 : bits;
}

bool try_get_global_type_bit(char type_code, int& bit_index) {
    switch (type_code) {
        case 'a':
            bit_index = 0;
            return true;
        case 'b':
            bit_index = 1;
            return true;
        case 'c':
            bit_index = 2;
            return true;
        case 'd':
            bit_index = 3;
            return true;
        case 'e':
            bit_index = 4;
            return true;
        case 'f':
            bit_index = 5;
            return true;
        case 'g':
            bit_index = 6;
            return true;
        case 'h':
            bit_index = 7;
            return true;
        case 'i':
            bit_index = 8;
            return true;
        case 'j':
            bit_index = 9;
            return true;
        case 'k':
            bit_index = 10;
            return true;
        case 'l':
            bit_index = 11;
            return true;
        case 'm':
            bit_index = 24;
            return true;
        default:
            bit_index = -1;
            return false;
    }
}

std::string lower_copy(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

auto equals_none = [](const std::string& s) {
    if (s.size() != 4) {
        return false;
    }
    return (s[0] == 'n' || s[0] == 'N') && (s[1] == 'o' || s[1] == 'O')
           && (s[2] == 'n' || s[2] == 'N') && (s[3] == 'e' || s[3] == 'E');
};

bool split_leaf_type_and_value(
    const std::string& s,
    std::string& type_name,
    std::string& value_str
) {
    const std::size_t pos = s.find('\'');
    if (pos == std::string::npos || s.empty() || s.back() != '\'' || pos == 0
        || pos >= s.size() - 1) {
        type_name.clear();
        value_str = s;
        return true;
    }
    type_name = s.substr(0, pos);
    value_str = s.substr(pos + 1, s.size() - pos - 2);
    return true;
}

bool is_meta_key(const std::string& key) {
    return key.rfind("__", 0) == 0;
}

std::size_t count_non_meta_keys(const nlohmann::ordered_json& obj) {
    if (!obj.is_object()) {
        return 0;
    }
    const bool is_wrapper = obj.contains("__typeFlags") && obj.contains("value");
    std::size_t count = 0;
    for (const auto& kv : obj.items()) {
        if (!is_meta_key(kv.key())) {
            if (is_wrapper && kv.key() == "value") {
                continue;
            }
            ++count;
        }
    }
    return count;
}

bool first_non_meta_kv(
    const nlohmann::ordered_json& obj,
    std::string& key_out,
    const nlohmann::ordered_json*& value_out
) {
    if (!obj.is_object()) {
        return false;
    }
    const bool is_wrapper = obj.contains("__typeFlags") && obj.contains("value");
    for (const auto& kv : obj.items()) {
        if (is_meta_key(kv.key())) {
            continue;
        }
        if (is_wrapper && kv.key() == "value") {
            continue;
        }
        key_out = kv.key();
        value_out = &kv.value();
        return true;
    }
    return false;
}

void record_flag(
    std::unordered_map<std::string, std::unordered_map<std::uint32_t, std::uint32_t>>& dst,
    const std::string& key,
    std::uint32_t flags
) {
    auto& inner = dst[key];
    auto it = inner.find(flags);
    if (it == inner.end()) {
        inner.emplace(flags, 1u);
    } else {
        it->second += 1u;
    }
}

const nlohmann::ordered_json& unwrap_typeflags_value(const nlohmann::ordered_json& node) {
    if (node.is_object() && node.contains("__typeFlags") && node.contains("value")) {
        return node.at("value");
    }
    return node;
}

std::string compute_array_signature(const nlohmann::ordered_json& arr) {
    if (!arr.is_array()) {
        return {};
    }
    if (arr.empty()) {
        return "empty";
    }

    bool all_leaf = true;
    bool all_map = true;
    bool all_array = true;
    bool leaf_type_set = false;
    std::string leaf_type_lower;
    bool leaf_type_mixed = false;

    for (const auto& el : arr) {
        const auto& item = unwrap_typeflags_value(el);
        if (item.is_string()) {
            all_map = false;
            all_array = false;
            std::string type_name;
            std::string value_str;
            if (!split_leaf_type_and_value(item.get<std::string>(), type_name, value_str)) {
                all_leaf = false;
                continue;
            }
            const std::string type_lower = lower_copy(type_name);
            if (!leaf_type_set) {
                leaf_type_lower = type_lower;
                leaf_type_set = true;
            } else if (type_lower != leaf_type_lower) {
                leaf_type_mixed = true;
            }
            continue;
        }
        if (item.is_object()) {
            all_leaf = false;
            all_array = false;
            continue;
        }
        if (item.is_array()) {
            all_leaf = false;
            all_map = false;
            continue;
        }
        all_leaf = false;
        all_map = false;
        all_array = false;
    }

    if (all_leaf && leaf_type_set) {
        if (leaf_type_mixed) {
            return "leaf:mix";
        }
        return std::string("leaf:") + leaf_type_lower;
    }
    if (all_map) {
        auto value_sig = [](const nlohmann::ordered_json& node) {
            if (node.is_null()) {
                return std::string("null");
            }
            if (node.is_string()) {
                std::string type_name;
                std::string value_str;
                split_leaf_type_and_value(node.get<std::string>(), type_name, value_str);
                return std::string("leaf:") + lower_copy(type_name);
            }
            if (node.is_array()) {
                return std::string("array");
            }
            if (node.is_object()) {
                return std::string("map");
            }
            return std::string("other");
        };

        bool sig_set = false;
        std::string base_sig;
        bool sig_mixed = false;
        for (const auto& el : arr) {
            const auto& item = unwrap_typeflags_value(el);
            if (!item.is_object()) {
                continue;
            }
            std::vector<std::string> parts;
            for (const auto& kv : item.items()) {
                if (kv.key().rfind("__", 0) == 0) {
                    continue;
                }
                std::string part = lower_copy(kv.key());
                part.push_back('=');
                part += value_sig(kv.value());
                parts.push_back(std::move(part));
            }
            std::sort(parts.begin(), parts.end());
            std::string sig = "map{";
            for (std::size_t i = 0; i < parts.size(); i++) {
                if (i != 0) {
                    sig.push_back(',');
                }
                sig.append(parts[i]);
            }
            sig.push_back('}');
            if (!sig_set) {
                base_sig = std::move(sig);
                sig_set = true;
            } else if (sig != base_sig) {
                sig_mixed = true;
                break;
            }
        }
        if (sig_mixed || !sig_set) {
            return "map:var";
        }
        return base_sig;
    }
    if (all_array) {
        return "array";
    }
    return "mixed";
}

bool has_empty_leaf(const nlohmann::ordered_json& node) {
    if (node.is_string()) {
        std::string type_name;
        std::string value_str;
        split_leaf_type_and_value(node.get<std::string>(), type_name, value_str);
        return value_str.empty();
    }
    if (node.is_array()) {
        for (const auto& el : node) {
            if (has_empty_leaf(el)) {
                return true;
            }
        }
        return false;
    }
    if (node.is_object()) {
        for (const auto& kv : node.items()) {
            if (kv.key().rfind("__", 0) == 0) {
                continue;
            }
            if (has_empty_leaf(kv.value())) {
                return true;
            }
        }
        return false;
    }
    return false;
}

bool looks_like_loc_string(const std::string& s) {
    if (s.empty()) {
        return false;
    }
    const auto c1 = s.find(',');
    if (c1 == std::string::npos) {
        return false;
    }
    const auto c2 = s.find(',', c1 + 1);
    if (c2 == std::string::npos) {
        return false;
    }
    std::string mid = s.substr(c1 + 1, c2 - c1 - 1);
    while (!mid.empty() && std::isspace(static_cast<unsigned char>(mid.front()))) {
        mid.erase(mid.begin());
    }
    while (!mid.empty() && std::isspace(static_cast<unsigned char>(mid.back()))) {
        mid.pop_back();
    }
    if (mid.size() != 32) {
        return false;
    }
    for (char ch : mid) {
        const bool is_hex =
            (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
        if (!is_hex) {
            return false;
        }
    }
    return true;
}

bool looks_like_dialog_facefx_animset_asset(const std::string& s) {
    if (s.find("FaceFXAnimSet_VOBD_") == std::string::npos) {
        return false;
    }
    return s.find("/Game/Dialog/FaceFXAnimSets/") != std::string::npos;
}

bool looks_like_vobd_name(const std::string& s) {
    return s.rfind("VOBD_", 0) == 0;
}

bool is_m_kind_name(const std::string& lower_type) {
    static const std::unordered_set<std::string> kinds = {
        "dialogevent",
        "dialognametag",
        "dialogparameter",
        "dialogquiettime",
        "dialogscript",
        "game_region",
        "gbxactor",
        "gore",
        "loadingscreen_data",
        "mission",
        "progress_graph_group",
        "progression",
        "skill",
        "skill_component_identifier",
        "skill_condition_ref",
        "skill_state",
        "stance",
    };
    return kinds.find(lower_type) != kinds.end();
}

std::uint32_t compute_node_type_mask(const nlohmann::ordered_json& node) {
    const auto& actual = unwrap_typeflags_value(node);
    int kind = 0;
    if (actual.is_null()) {
        kind = 0;
    } else if (actual.is_string()) {
        kind = 1;
    } else if (actual.is_array()) {
        kind = 2;
    } else if (actual.is_object()) {
        kind = 3;
    }

    std::uint32_t mask = static_cast<std::uint32_t>(kind & 3);
    if (kind == 0) {
        return 0;
    }
    mask |= 1u << 9;  // 'j'

    if (kind == 1) {
        std::string value_type;
        std::string value_str;
        if (!split_leaf_type_and_value(actual.get<std::string>(), value_type, value_str)) {
            return mask;
        }
        const std::string value_type_lower = lower_copy(value_type);
        if (value_type_lower == "asset") {
            mask |= 1u << 8;  // 'i'
        }
        if (looks_like_loc_string(value_str)) {
            mask |= 1u << 11;  // 'l'
        }
        if (value_str.empty()) {
            mask |= 1u << 5;  // 'f'
        }
        if (!value_type_lower.empty()) {
            if (is_m_kind_name(value_type_lower)) {
                mask |= 1u << 24;  // 'm'
            } else if (value_type_lower == "asset"
                       && looks_like_dialog_facefx_animset_asset(value_str)) {
                mask |= 1u << 24;  // 'm'
            }
        } else if (looks_like_vobd_name(value_str)) {
            mask |= 1u << 24;  // 'm'
        }
    }

    return mask;
}

std::uint32_t compute_expected_mask(
    const nlohmann::ordered_json& node,
    std::string_view parent_key,
    const std::vector<std::uint32_t>& row_flags
) {
    const auto& actual = unwrap_typeflags_value(node);
    if (&actual != &node) {
        return compute_expected_mask(actual, parent_key, row_flags);
    }
    if (actual.is_object() && count_non_meta_keys(actual) == 1) {
        std::string key;
        const nlohmann::ordered_json* inner = nullptr;
        if (first_non_meta_kv(actual, key, inner) && inner != nullptr) {
            if (!inner->is_object() && !equals_none(key)) {
                const std::uint32_t want_mask = compute_node_type_mask(*inner) | 0x80u;
                for (const auto& f : row_flags) {
                    if (f == want_mask) {
                        return want_mask;
                    }
                }
            }
        }
    }

    std::uint32_t mask = compute_node_type_mask(actual);
    return mask;
}

std::vector<std::uint32_t> collect_shape_matching_masks(
    const nlohmann::ordered_json& node,
    const std::vector<std::uint32_t>& row_flags
) {
    const auto& actual = unwrap_typeflags_value(node);
    std::vector<std::uint32_t> matches;
    matches.reserve(row_flags.size());

    auto add_unique = [&matches](std::uint32_t mask) {
        for (const auto& v : matches) {
            if (v == mask) {
                return;
            }
        }
        matches.push_back(mask);
    };

    auto add_by_base = [&](std::uint32_t base_mask, bool require_self, int kind) {
        const std::uint32_t base_no_self = base_mask & ~0x80u;
        for (const auto& f : row_flags) {
            if ((f & ~0x80u) != base_no_self) {
                continue;
            }
            if ((f & 3u) != static_cast<std::uint32_t>(kind)) {
                continue;
            }
            if (require_self && (f & 0x80u) == 0u) {
                continue;
            }
            if (!require_self && (f & 0x80u) != 0u) {
                continue;
            }
            add_unique(f);
        }
    };

    if (actual.is_null()) {
        add_by_base(0u, false, 0);
        return matches;
    }
    if (actual.is_string()) {
        add_by_base(compute_node_type_mask(actual), false, 1);
        return matches;
    }
    if (actual.is_array()) {
        add_by_base(compute_node_type_mask(actual), false, 2);
        return matches;
    }
    if (!actual.is_object()) {
        return matches;
    }

    std::string key;
    const nlohmann::ordered_json* inner = nullptr;
    if (count_non_meta_keys(actual) == 1 && first_non_meta_kv(actual, key, inner) && inner) {
        const auto& inner_actual = unwrap_typeflags_value(*inner);
        if (!inner_actual.is_object()) {
            if (inner_actual.is_array()) {
                add_by_base(compute_node_type_mask(inner_actual), true, 2);
            } else if (inner_actual.is_string()) {
                add_by_base(compute_node_type_mask(inner_actual), true, 1);
            } else if (inner_actual.is_null()) {
                add_by_base(compute_node_type_mask(inner_actual), true, 0);
            }
            const std::uint32_t base_outer = compute_node_type_mask(actual);
            for (const auto& f : row_flags) {
                if ((f & ~0x80u) == (base_outer & ~0x80u) && (f & 3u) == 3u) {
                    add_unique(f);
                }
            }
            return matches;
        }
    }

    const std::uint32_t base_outer = compute_node_type_mask(actual);
    for (const auto& f : row_flags) {
        if ((f & ~0x80u) == (base_outer & ~0x80u) && (f & 3u) == 3u) {
            add_unique(f);
        }
    }
    return matches;
}

struct DecodeContext {
    std::vector<std::uint32_t> row_flags;
    int type_index_bits = 0;
    const std::vector<std::string>* value_strings = nullptr;
    int value_index_bits = 0;
    const std::vector<std::string>* value_kinds = nullptr;
    int value_kind_index_bits = 0;
    const std::vector<std::string>* key_strings = nullptr;
    int key_index_bits = 0;
    std::unordered_map<std::uint64_t, std::vector<std::uint32_t>> mask_buckets;
};

struct DecodeOverrideState {
    std::unordered_map<std::uint32_t, std::uint32_t>* overrides = nullptr;
    std::uint32_t* node_index = nullptr;
    int record_end_bit = -1;
    bool emit_all_type_flags = false;
    bool debug_progress = false;
};

DecodeContext build_context(const TypeCodeTable& t) {
    DecodeContext ctx{};
    const std::string& type_codes = t.header.type_codes;
    ctx.row_flags.resize(t.header.type_index_count);
    for (std::size_t row = 0; row < t.header.matrix_row_masks.size(); row++) {
        const std::uint64_t row_mask_cols = t.header.matrix_row_masks[row];
        std::uint32_t flags = 0;
        for (std::size_t col = 0; col < type_codes.size(); col++) {
            if (((row_mask_cols >> col) & 1u) == 0) {
                continue;
            }
            int bit_index = -1;
            if (!try_get_global_type_bit(type_codes[col], bit_index)) {
                continue;
            }
            if (bit_index >= 0 && bit_index < 32) {
                flags |= 1u << bit_index;
            }
        }
        ctx.row_flags[row] = flags;
    }
    ctx.mask_buckets.reserve(ctx.row_flags.size());
    auto make_bucket_key = [](std::uint32_t base_no_self, std::uint8_t kind,
                              bool self) -> std::uint64_t {
        return static_cast<std::uint64_t>(base_no_self) | (static_cast<std::uint64_t>(kind) << 32)
               | (static_cast<std::uint64_t>(self ? 1 : 0) << 40);
    };
    for (const auto f : ctx.row_flags) {
        const std::uint32_t base_no_self = f & ~0x80u;
        const std::uint8_t kind = static_cast<std::uint8_t>(f & 3u);
        const bool self = (f & 0x80u) != 0u;
        const std::uint64_t key = make_bucket_key(base_no_self, kind, self);
        auto& bucket = ctx.mask_buckets[key];
        bool exists = false;
        for (const auto v : bucket) {
            if (v == f) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            bucket.push_back(f);
        }
    }

    ctx.type_index_bits = index_bits(t.header.type_index_count);
    ctx.value_strings = &t.value_strings;
    ctx.value_index_bits =
        index_bits(static_cast<int>(std::max<std::uint32_t>(1u, t.value_strings_declared_count)));
    ctx.value_kinds = t.tables.size() > 0 ? &t.tables[0].strings : nullptr;
    ctx.value_kind_index_bits = index_bits(
        t.tables.size() > 0
            ? static_cast<int>(std::max<std::uint32_t>(1u, t.tables[0].declared_count))
            : 1
    );
    ctx.key_strings = t.tables.size() > 1 ? &t.tables[1].strings : nullptr;
    ctx.key_index_bits = index_bits(
        t.tables.size() > 1
            ? static_cast<int>(std::max<std::uint32_t>(1u, t.tables[1].declared_count))
            : 1
    );
    return ctx;
}

struct FixedWidthIntArray24 {
    int count = 0;
    int value_bit_width = 0;
    int index_bit_width = 0;
    std::vector<int> values;

    bool is_active() const {
        return count > 0 && value_bit_width > 0 && index_bit_width > 0
               && static_cast<int>(values.size()) == count;
    }
};

FixedWidthIntArray24 read_fixed_width_int_array24(BitReader& br) {
    FixedWidthIntArray24 out{};
    out.count = static_cast<int>(br.read_bits(24));
    out.value_bit_width = static_cast<int>(br.read_bits(8));
    out.index_bit_width = out.count > 0 ? index_bits(out.count) : 0;

    if (out.count <= 0 || out.value_bit_width <= 0) {
        return out;
    }

    if (out.value_bit_width > 32) {
        const long long bits_to_skip =
            static_cast<long long>(out.count) * static_cast<long long>(out.value_bit_width);
        if (bits_to_skip < 0 || br.bit_position() + bits_to_skip > br.bit_length()) {
            std::string msg = "FixedWidthIntArray24 skip out of range";
            msg += " count=";
            msg += std::to_string(out.count);
            msg += " bitWidth=";
            msg += std::to_string(out.value_bit_width);
            msg += " bitPos=";
            msg += std::to_string(br.bit_position());
            msg += " bitLen=";
            msg += std::to_string(br.bit_length());
            throw std::runtime_error(std::move(msg));
        }
        br.skip_bits(bits_to_skip);
        return out;
    }

    if (out.count > 1000000) {
        throw std::runtime_error(std::string("FixedWidthIntArray24 count too large"));
    }

    out.values.resize(static_cast<std::size_t>(out.count));
    for (int i = 0; i < out.count; i++) {
        out.values[static_cast<std::size_t>(i)] =
            static_cast<int>(br.read_bits(out.value_bit_width));
    }
    return out;
}

std::string read_pair_vec_string(
    BitReader& br,
    const DecodeContext& ctx,
    const FixedWidthIntArray24* pair_vec_remap
) {
    int raw_bits = (pair_vec_remap && pair_vec_remap->index_bit_width > 0)
                       ? pair_vec_remap->index_bit_width
                       : ctx.key_index_bits;
    const std::uint32_t raw_index = br.read_bits(raw_bits);

    int mapped = static_cast<int>(raw_index);
    if (pair_vec_remap) {
        if (raw_index >= static_cast<std::uint32_t>(pair_vec_remap->count)) {
            return {};
        }
        mapped = pair_vec_remap->values[static_cast<std::size_t>(raw_index)];
    }

    if (!ctx.key_strings) {
        return {};
    }
    return (mapped >= 0 && mapped < static_cast<int>(ctx.key_strings->size()))
               ? (*ctx.key_strings)[static_cast<std::size_t>(mapped)]
               : std::string{};
}

void skip_pair_vec_index(
    BitReader& br,
    const DecodeContext& ctx,
    const FixedWidthIntArray24* pair_vec_remap
) {
    const int raw_bits = (pair_vec_remap && pair_vec_remap->index_bit_width > 0)
                             ? pair_vec_remap->index_bit_width
                             : ctx.key_index_bits;
    br.read_bits(raw_bits);
}

void skip_packed_name_list(
    BitReader& br,
    const DecodeContext& ctx,
    const FixedWidthIntArray24* pair_vec_remap
) {
    for (int guard = 0; guard < 4096; guard++) {
        std::string s = read_pair_vec_string(br, ctx, pair_vec_remap);
        if (s.empty()) {
            break;
        }
        if (s.size() == 4) {
            const auto lower = [](char c) {
                return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            };
            if (lower(s[0]) == 'n' && lower(s[1]) == 'o' && lower(s[2]) == 'n'
                && lower(s[3]) == 'e') {
                break;
            }
        }
    }
}

std::string decode_value(
    BitReader& br,
    const DecodeContext& ctx,
    const FixedWidthIntArray24* value_string_remap
) {
    const int value_raw_bits = (value_string_remap && value_string_remap->index_bit_width > 0)
                                   ? value_string_remap->index_bit_width
                                   : ctx.value_index_bits;

    const std::uint32_t raw_index = br.read_bits(value_raw_bits);
    int value_index = static_cast<int>(raw_index);
    if (value_string_remap) {
        if (raw_index >= static_cast<std::uint32_t>(value_string_remap->count)) {
            value_index = -1;
        } else {
            value_index = value_string_remap->values[static_cast<std::size_t>(raw_index)];
        }
    }

    const std::uint32_t kind_index_u = br.read_bits(ctx.value_kind_index_bits);
    const int kind_index = static_cast<int>(kind_index_u);

    const std::string value = (ctx.value_strings && value_index >= 0
                               && value_index < static_cast<int>(ctx.value_strings->size()))
                                  ? (*ctx.value_strings)[static_cast<std::size_t>(value_index)]
                                  : std::string{};

    const std::string type_name = (ctx.value_kinds && kind_index >= 0
                                   && kind_index < static_cast<int>(ctx.value_kinds->size()))
                                      ? (*ctx.value_kinds)[static_cast<std::size_t>(kind_index)]
                                      : std::string{};

    if (type_name.empty()) {
        return value;
    }

    std::string out;
    out.reserve(type_name.size() + value.size() + 2);
    out.append(type_name);
    out.push_back('\'');
    out.append(value);
    out.push_back('\'');
    return out;
}

void skip_value(
    BitReader& br,
    const DecodeContext& ctx,
    const FixedWidthIntArray24* value_string_remap
) {
    const int value_raw_bits = (value_string_remap && value_string_remap->index_bit_width > 0)
                                   ? value_string_remap->index_bit_width
                                   : ctx.value_index_bits;
    br.read_bits(value_raw_bits);
    br.read_bits(ctx.value_kind_index_bits);
}

nlohmann::ordered_json decode_node(
    BitReader& br,
    const DecodeContext& ctx,
    const FixedWidthIntArray24* pair_vec_remap,
    const FixedWidthIntArray24* value_string_remap,
    TypeFlagStats* stats,
    DecodeOverrideState* override_state,
    std::string_view parent_key
);

void skip_node(
    BitReader& br,
    const DecodeContext& ctx,
    const FixedWidthIntArray24* pair_vec_remap,
    const FixedWidthIntArray24* value_string_remap,
    DecodeOverrideState* override_state
);

nlohmann::ordered_json decode_array(
    BitReader& br,
    const DecodeContext& ctx,
    const FixedWidthIntArray24* pair_vec_remap,
    const FixedWidthIntArray24* value_string_remap,
    TypeFlagStats* stats,
    DecodeOverrideState* override_state
) {
    nlohmann::ordered_json arr = nlohmann::ordered_json::array();
    const int limit = (override_state && override_state->record_end_bit >= 0)
                          ? override_state->record_end_bit
                          : br.bit_length();
    while (br.bit_position() < limit && br.read_bit()) {
        arr.push_back(decode_node(
            br, ctx, pair_vec_remap, value_string_remap, stats, override_state, std::string_view{}
        ));
    }
    return arr;
}

nlohmann::ordered_json decode_map(
    BitReader& br,
    const DecodeContext& ctx,
    const FixedWidthIntArray24* pair_vec_remap,
    const FixedWidthIntArray24* value_string_remap,
    TypeFlagStats* stats,
    DecodeOverrideState* override_state
) {
    nlohmann::ordered_json obj = nlohmann::ordered_json::object();
    const int limit = (override_state && override_state->record_end_bit >= 0)
                          ? override_state->record_end_bit
                          : br.bit_length();
    while (br.bit_position() < limit && br.read_bit()) {
        const std::string k = read_pair_vec_string(br, ctx, pair_vec_remap);
        obj[k] = decode_node(br, ctx, pair_vec_remap, value_string_remap, stats, override_state, k);
    }
    return obj;
}

void skip_array(
    BitReader& br,
    const DecodeContext& ctx,
    const FixedWidthIntArray24* pair_vec_remap,
    const FixedWidthIntArray24* value_string_remap,
    DecodeOverrideState* override_state
) {
    const int limit = (override_state && override_state->record_end_bit >= 0)
                          ? override_state->record_end_bit
                          : br.bit_length();
    while (br.bit_position() < limit && br.read_bit()) {
        skip_node(br, ctx, pair_vec_remap, value_string_remap, override_state);
    }
}

void skip_map(
    BitReader& br,
    const DecodeContext& ctx,
    const FixedWidthIntArray24* pair_vec_remap,
    const FixedWidthIntArray24* value_string_remap,
    DecodeOverrideState* override_state
) {
    const int limit = (override_state && override_state->record_end_bit >= 0)
                          ? override_state->record_end_bit
                          : br.bit_length();
    while (br.bit_position() < limit && br.read_bit()) {
        skip_pair_vec_index(br, ctx, pair_vec_remap);
        skip_node(br, ctx, pair_vec_remap, value_string_remap, override_state);
    }
}

void skip_node(
    BitReader& br,
    const DecodeContext& ctx,
    const FixedWidthIntArray24* pair_vec_remap,
    const FixedWidthIntArray24* value_string_remap,
    DecodeOverrideState* override_state
) {
    const std::uint32_t type_index = br.read_bits(ctx.type_index_bits);
    const std::uint32_t flags = (type_index < ctx.row_flags.size())
                                    ? ctx.row_flags[static_cast<std::size_t>(type_index)]
                                    : 0u;

    const int kind = static_cast<int>(flags & 3u);
    const bool has_self_key = kind == 3 || (flags & 0x80u) != 0;
    if (has_self_key) {
        skip_pair_vec_index(br, ctx, pair_vec_remap);
    }

    switch (kind) {
        case 0:
            break;
        case 1:
            skip_value(br, ctx, value_string_remap);
            break;
        case 2:
            skip_array(br, ctx, pair_vec_remap, value_string_remap, override_state);
            break;
        case 3:
            skip_map(br, ctx, pair_vec_remap, value_string_remap, override_state);
            break;
        default:
            break;
    }
}

nlohmann::ordered_json decode_node(
    BitReader& br,
    const DecodeContext& ctx,
    const FixedWidthIntArray24* pair_vec_remap,
    const FixedWidthIntArray24* value_string_remap,
    TypeFlagStats* stats,
    DecodeOverrideState* override_state,
    std::string_view parent_key
) {
    std::uint32_t node_index = 0;
    if (override_state && override_state->node_index) {
        node_index = (*override_state->node_index)++;
        if ((stats || override_state->debug_progress) && (node_index % 100000u) == 0u) {
            BL4_LOG_INFO("    nodes=%u bit=%d", node_index, br.bit_position());
        }
    }

    const std::uint32_t type_index = br.read_bits(ctx.type_index_bits);
    const std::uint32_t flags = (type_index < ctx.row_flags.size())
                                    ? ctx.row_flags[static_cast<std::size_t>(type_index)]
                                    : 0u;

    const int kind = static_cast<int>(flags & 3u);
    const bool has_self_key = kind == 3 || (flags & 0x80u) != 0;
    std::string self_key;
    if (has_self_key) {
        self_key = read_pair_vec_string(br, ctx, pair_vec_remap);
    }

    nlohmann::ordered_json value;
    switch (kind) {
        case 0:
            value = nullptr;
            break;
        case 1:
            value = decode_value(br, ctx, value_string_remap);
            break;
        case 2:
            value =
                decode_array(br, ctx, pair_vec_remap, value_string_remap, stats, override_state);
            break;
        case 3:
            value = decode_map(br, ctx, pair_vec_remap, value_string_remap, stats, override_state);
            break;
        default: {
            nlohmann::ordered_json dbg = nlohmann::ordered_json::object();
            dbg["_kind"] = kind;
            dbg["_flags"] = flags;
            dbg["_typeIndex"] = type_index;
            value = std::move(dbg);
            break;
        }
    }

    if (stats) {
        if (kind == 1 && value.is_string()) {
            std::string type_name;
            std::string value_str;
            split_leaf_type_and_value(value.get<std::string>(), type_name, value_str);
            const std::string type_lower = lower_copy(type_name);
            record_flag(stats->leaf_flags, type_lower, flags);
            if (!value_str.empty()) {
                std::string value_key = type_lower;
                value_key.push_back('|');
                value_key += lower_copy(value_str);
                record_flag(stats->leaf_value_flags, value_key, flags);
            }
            if (!parent_key.empty()) {
                std::string key = lower_copy(parent_key);
                key.push_back('|');
                key += type_lower;
                record_flag(stats->leaf_parent_flags, key, flags);
            }
        } else if (kind == 2 && value.is_array()) {
            if (!parent_key.empty()) {
                const std::string signature = compute_array_signature(value);
                std::string key = lower_copy(parent_key);
                key.push_back('|');
                key += lower_copy(signature);
                record_flag(stats->array_flags, key, flags);

                const std::size_t len = value.size();
                std::string len_sig;
                if (len <= 3) {
                    len_sig = std::to_string(len);
                } else {
                    len_sig = "gt3";
                }
                const bool empty_leaf = has_empty_leaf(value);
                std::string detail = key;
                detail.append("|len=");
                detail.append(len_sig);
                detail.append("|empty=");
                detail.append(empty_leaf ? "1" : "0");
                record_flag(stats->array_flags, detail, flags);
            }
        }
    }

    nlohmann::ordered_json out_value = value;
    if (!self_key.empty() && !equals_none(self_key)) {
        nlohmann::ordered_json wrap = nlohmann::ordered_json::object();
        wrap[self_key] = value;
        out_value = std::move(wrap);
    }

    const bool force_type_flags = override_state && override_state->emit_all_type_flags;
    if (force_type_flags) {
        nlohmann::ordered_json wrap = nlohmann::ordered_json::object();
        wrap["__typeFlags"] = flags;
        wrap["value"] = std::move(out_value);
        out_value = std::move(wrap);
        return out_value;
    }

    const auto matches = collect_shape_matching_masks(out_value, ctx.row_flags);
    const bool ambiguous = !(matches.size() == 1 && matches[0] == flags);
    const std::uint32_t expected = compute_expected_mask(out_value, parent_key, ctx.row_flags);
    if (expected != flags || ambiguous) {
        if (override_state && override_state->overrides && override_state->node_index) {
            (*override_state->overrides)[node_index] = flags;
        }
        nlohmann::ordered_json wrap = nlohmann::ordered_json::object();
        wrap["__typeFlags"] = flags;
        wrap["value"] = std::move(out_value);
        out_value = std::move(wrap);
    }

    return out_value;
}

std::vector<std::string> read_packed_name_list(
    BitReader& br,
    const DecodeContext& ctx,
    const FixedWidthIntArray24* pair_vec_remap
) {
    std::vector<std::string> list;
    for (int guard = 0; guard < 4096; guard++) {
        std::string s = read_pair_vec_string(br, ctx, pair_vec_remap);
        if (s.empty()) {
            break;
        }
        if (s.size() == 4) {
            const auto lower = [](char c) {
                return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            };
            if (lower(s[0]) == 'n' && lower(s[1]) == 'o' && lower(s[2]) == 'n'
                && lower(s[3]) == 'e') {
                break;
            }
        }
        list.push_back(std::move(s));
    }
    return list;
}

TableDataDecodeResult decode_table_data(
    const TypeCodeTable& type_code_table,
    const DecompBlob& decomp,
    std::string_view file_label,
    TypeFlagStats* out_stats,
    DecodeOptions options
) {
    TableDataDecodeResult result{};
    options.emit_all_type_flags = true;
    if (options.emit_all_type_flags) {
        options.collect_type_flag_overrides = false;
    }
    const DecodeContext ctx = build_context(type_code_table);
    BitReader br(type_code_table.data_span());
    std::unordered_map<std::uint32_t, std::uint32_t> type_flag_overrides;
    std::uint32_t node_index = 0;
    DecodeOverrideState override_state{};
    if (options.collect_type_flag_overrides) {
        override_state.overrides = &type_flag_overrides;
        override_state.node_index = &node_index;
    }
    if (options.debug_progress && !override_state.node_index) {
        override_state.node_index = &node_index;
    }
    override_state.emit_all_type_flags = options.emit_all_type_flags;
    override_state.debug_progress = options.debug_progress;
    override_state.record_end_bit = -1;

    const int table_id_bits = index_bits(static_cast<int>(decomp.strings.size()));
    int last_table_terminator_end_bit = -1;
    auto has_bits = [&br](int bit_count) -> bool {
        return bit_count >= 0 && br.bit_position() + bit_count <= br.bit_length();
    };

    struct TableTrace {
        int start_bit = 0;
        std::uint32_t id = 0;
        std::string name;
    };
    std::array<TableTrace, 8> last_tables{};
    std::size_t last_table_cursor = 0;
    std::size_t last_table_count = 0;
    auto note_table_start = [&](int start_bit, std::uint32_t id, std::string name) {
        last_tables[last_table_cursor] = TableTrace{start_bit, id, std::move(name)};
        last_table_cursor = (last_table_cursor + 1) % last_tables.size();
        last_table_count = std::min<std::size_t>(last_tables.size(), last_table_count + 1);
    };

    const char* phase = "init";
    int current_record_index = -1;
    std::uint64_t total_records = 0;
    const bool trace_progress = out_stats != nullptr || options.debug_progress;
    try {
        while (has_bits(table_id_bits)) {
            const int table_start_bit = br.bit_position();
            phase = "table_id";
            const std::uint32_t table_id = br.read_bits(table_id_bits);
            if (table_id == 0) {
                break;
            }

            if (table_id >= decomp.strings.size()) {
                break;
            }
            // Table body always begins with at least one table-id sentinel for the deps list.
            // EOF is treated as end-of-stream padding.
            if (!has_bits(table_id_bits)) {
                break;
            }

            std::string name = decomp.strings[static_cast<std::size_t>(table_id)];
            if (name.empty()) {
                name = "<empty:" + std::to_string(table_id) + ">";
            }
            if (trace_progress) {
                BL4_LOG_INFO(
                    "Decode table: %s (id=%u) bit=%d", name.c_str(), table_id, table_start_bit
                );
            }
            note_table_start(table_start_bit, table_id, name);

            nlohmann::ordered_json table_obj = nlohmann::ordered_json::object();

            std::vector<std::uint32_t> deps;
            phase = "deps";
            for (int guard = 0; guard < 1024; guard++) {
                if (!has_bits(table_id_bits)) {
                    // No deps terminator; EOF is treated as end-of-stream padding.
                    break;
                }
                const std::uint32_t dep = br.read_bits(table_id_bits);
                if (dep == 0) {
                    break;
                }
                deps.push_back(dep);
            }

            FixedWidthIntArray24 remap_a{};
            FixedWidthIntArray24 remap_b{};
            try {
                auto read_remap_forgiving = [&](FixedWidthIntArray24& dst, const char* which) {
                    const int start_bit = br.bit_position();
                    try {
                        dst = read_fixed_width_int_array24(br);
                        if (dst.count > 0 && dst.value_bit_width <= 0) {
                            throw std::runtime_error(
                                "FixedWidthIntArray24 invalid header (width<=0 with count>0)"
                            );
                        }
                        return;
                    } catch (const std::exception&) {
                        br.seek(start_bit);
                        br.align_to_byte();
                        const int aligned_bit = br.bit_position();
                        if (aligned_bit == start_bit) {
                            throw;
                        }
                        dst = read_fixed_width_int_array24(br);
                        if (dst.count > 0 && dst.value_bit_width <= 0) {
                            throw std::runtime_error(
                                "FixedWidthIntArray24 invalid header (width<=0 with count>0)"
                            );
                        }
                    }
                };

                phase = "remap_a";
                if (!has_bits(32)) {
                    break;
                }
                read_remap_forgiving(remap_a, "remap_a");
                phase = "remap_b";
                if (!has_bits(32)) {
                    break;
                }
                read_remap_forgiving(remap_b, "remap_b");
            } catch (const std::exception& ex) {
                if (!result.warning_or_error.has_value()) {
                    std::string msg = "Decode failed";
                    msg += " file='";
                    msg += file_label;
                    msg += "' table='";
                    msg += name;
                    msg += "' phase=";
                    msg += phase;
                    msg += " bitPos=";
                    msg += std::to_string(br.bit_position());
                    msg += ": ";
                    msg += ex.what();
                    result.warning_or_error = std::move(msg);
                }
                break;
            }
            const FixedWidthIntArray24* pair_vec_remap = remap_a.is_active() ? &remap_a : nullptr;
            const FixedWidthIntArray24* value_string_remap =
                remap_b.is_active() ? &remap_b : nullptr;

            auto remap_to_json = [](const FixedWidthIntArray24& r) -> nlohmann::ordered_json {
                nlohmann::ordered_json out = nlohmann::ordered_json::object();
                out["count"] = r.count;
                out["valueBitWidth"] = r.value_bit_width;
                nlohmann::ordered_json values = nlohmann::ordered_json::array();
                for (const int v : r.values) {
                    values.push_back(v);
                }
                out["values"] = std::move(values);
                return out;
            };

            if (options.collect_table_remaps) {
                nlohmann::ordered_json remaps = nlohmann::ordered_json::object();
                remaps["pairVec"] = remap_to_json(remap_a);
                remaps["valueStrings"] = remap_to_json(remap_b);
                result.table_remaps[name] = std::move(remaps);
            }

            if (!deps.empty()) {
                nlohmann::ordered_json deps_json = nlohmann::ordered_json::array();
                for (const auto dep_id : deps) {
                    const std::string dep_name =
                        dep_id < decomp.strings.size()
                            ? decomp.strings[static_cast<std::size_t>(dep_id)]
                            : std::string{};
                    deps_json.push_back(dep_name);
                }
                table_obj["__deps"] = std::move(deps_json);
            }

            br.align_to_byte();
            nlohmann::ordered_json records = nlohmann::ordered_json::array();
            nlohmann::ordered_json record_tails = options.collect_record_tails
                                                      ? nlohmann::ordered_json::object()
                                                      : nlohmann::ordered_json();
            nlohmann::ordered_json record_tags = options.collect_record_tags
                                                     ? nlohmann::ordered_json::object()
                                                     : nlohmann::ordered_json();

            int record_index = 0;
            while (true) {
                current_record_index = record_index;
                if (trace_progress && (record_index == 0 || (record_index % 10000) == 0)) {
                    BL4_LOG_INFO(
                        "  record %d (total=%llu) bit=%d", record_index,
                        static_cast<unsigned long long>(total_records), br.bit_position()
                    );
                }
                br.align_to_byte();
                const int record_header_start_bit = br.bit_position();
                if (br.bit_position() + 32 > br.bit_length()) {
                    break;
                }
                std::uint32_t record_len_bytes = 0;
                try {
                    record_len_bytes = br.read_bits(32);
                } catch (const std::exception& ex) {
                    if (!result.warning_or_error.has_value()) {
                        std::string msg = "Decode failed";
                        msg += " file='";
                        msg += file_label;
                        msg += "' table='";
                        msg += name;
                        msg += "' record=";
                        msg += std::to_string(record_index);
                        msg += " bitPos=";
                        msg += std::to_string(record_header_start_bit);
                        msg += ": ";
                        msg += ex.what();
                        result.warning_or_error = std::move(msg);
                    }
                    break;
                }
                if (record_len_bytes == 0) {
                    // Table terminator: after the 0 length field, the stream includes an 8-bit 'z'
                    // marker. If we don't consume it, the next table-id read is misaligned (and
                    // subsequent remap headers break).
                    if (has_bits(8)) {
                        const std::uint8_t terminator = static_cast<std::uint8_t>(br.read_bits(8));
                        last_table_terminator_end_bit = br.bit_position();
#if defined(_DEBUG)
                        if (terminator != static_cast<std::uint8_t>('z')) {
                            if (!result.warning_or_error.has_value()) {
                                std::string msg = "Decode warning";
                                msg += " file='";
                                msg += file_label;
                                msg += "' table='";
                                msg += name;
                                msg += "' recordTerminator expected 'z' got=0x";
                                char hexbuf[3] = {0, 0, 0};
                                static const char hexdig[] = "0123456789ABCDEF";
                                hexbuf[0] = hexdig[(terminator >> 4) & 0xF];
                                hexbuf[1] = hexdig[terminator & 0xF];
                                msg += hexbuf;
                                msg += " bitPos=";
                                msg += std::to_string(br.bit_position() - 8);
                                result.warning_or_error = std::move(msg);
                            }
                        }
#endif
                    }
                    break;
                }

                const long long record_end_bit_long =
                    static_cast<long long>(record_header_start_bit)
                    + static_cast<long long>(record_len_bytes) * 8LL;
                if (record_end_bit_long > br.bit_length()) {
                    break;
                }
                const int record_end_bit = static_cast<int>(record_end_bit_long) & ~7;
                override_state.record_end_bit = record_end_bit;
                if (trace_progress && (record_index == 0 || (record_index % 10000) == 0)) {
                    BL4_LOG_INFO("    record_len=%u end_bit=%d", record_len_bytes, record_end_bit);
                }

                nlohmann::ordered_json record = nlohmann::ordered_json::object();
                nlohmann::ordered_json tags = options.collect_record_tags
                                                  ? nlohmann::ordered_json::array()
                                                  : nlohmann::ordered_json();
                bool tag_failed = false;
                int failed_tag_bitpos = -1;
                std::uint8_t failed_tag = 0;
                const char* failed_tag_reason = nullptr;
                int tag_count = 0;

                phase = "tags";
                while (br.bit_position() + 8 <= record_end_bit) {
                    const int tag_start_bit = br.bit_position();
                    const std::uint8_t tag = static_cast<std::uint8_t>(br.read_bits(8));
                    if (tag == static_cast<std::uint8_t>('z')) {
                        break;
                    }

                    nlohmann::ordered_json tag_obj = options.collect_record_tags
                                                         ? nlohmann::ordered_json::object()
                                                         : nlohmann::ordered_json();
                    if (options.collect_record_tags) {
                        tag_obj["__tag"] = std::string(1, static_cast<char>(tag));
                    }

                    try {
                        switch (static_cast<char>(tag)) {
                            case 'a': {
                                if (options.collect_record_tags) {
                                    tag_obj["pair"] = read_pair_vec_string(br, ctx, pair_vec_remap);
                                } else {
                                    skip_pair_vec_index(br, ctx, pair_vec_remap);
                                }
                                break;
                            }
                            case 'b': {
                                const std::uint32_t u = br.read_bits(32);
                                if (options.collect_record_tags) {
                                    tag_obj["u32"] = u;
                                }
                                break;
                            }
                            case 'c': {
                                const std::uint32_t u = br.read_bits(32);
                                float f;
                                std::memcpy(&f, &u, sizeof(float));
                                if (options.collect_record_tags) {
                                    tag_obj["u32"] = u;
                                    tag_obj["f32"] = f;
                                }
                                break;
                            }
                            case 'd':
                            case 'e':
                            case 'f': {
                                if (options.collect_record_tags) {
                                    tag_obj["list"] =
                                        read_packed_name_list(br, ctx, pair_vec_remap);
                                } else {
                                    skip_packed_name_list(br, ctx, pair_vec_remap);
                                }
                                break;
                            }
                            case 'p': {
                                if (options.collect_record_tags) {
                                    tag_obj["variant"] = decode_node(
                                        br, ctx, pair_vec_remap, value_string_remap, out_stats,
                                        &override_state, std::string_view{}
                                    );
                                } else {
                                    skip_node(
                                        br, ctx, pair_vec_remap, value_string_remap, &override_state
                                    );
                                }
                                break;
                            }
                            default:
                                tag_failed = true;
                                failed_tag_reason = "unknown_tag";
                                break;
                        }
                    } catch (...) {
                        tag_failed = true;
                        failed_tag_reason = "exception";
                    }

                    if (options.collect_record_tags) {
                        tags.push_back(tag_obj);
                    }
                    tag_count++;
                    if (trace_progress && (tag_count % 10000) == 0) {
                        BL4_LOG_INFO("    tags=%d bit=%d", tag_count, br.bit_position());
                    }
                    if (tag_failed) {
                        failed_tag = tag;
                        failed_tag_bitpos = tag_start_bit;
                        break;
                    }
                }
                if (trace_progress && record_index == 0) {
                    BL4_LOG_INFO("    tags_end count=%d bit=%d", tag_count, br.bit_position());
                }

                if (options.collect_record_tags && !tags.empty()) {
                    record_tags[std::to_string(record_index)] = std::move(tags);
                }
#if defined(_DEBUG)
                if (tag_failed) {
                    const char c = static_cast<char>(failed_tag);
                    const bool printable = std::isprint(static_cast<unsigned char>(c)) != 0;
                    const std::string tag_repr = printable ? std::string(1, c) : std::string("?");
                    std::string diag = "TagFailure";
                    diag += " file='";
                    diag += file_label;
                    diag += "' table='";
                    diag += name;
                    diag += "' record=";
                    diag += std::to_string(record_index);
                    diag += " tag=0x";
                    char hexbuf[3] = {0, 0, 0};
                    static const char hexdig[] = "0123456789ABCDEF";
                    hexbuf[0] = hexdig[(failed_tag >> 4) & 0xF];
                    hexbuf[1] = hexdig[failed_tag & 0xF];
                    diag += hexbuf;
                    diag += " ('";
                    diag += tag_repr;
                    diag += "')";
                    diag += " bitPos=";
                    diag += std::to_string(failed_tag_bitpos);
                    if (failed_tag_reason) {
                        diag += " reason=";
                        diag += failed_tag_reason;
                    }
                    result.tag_failures.push_back(std::move(diag));
                    if (!result.warning_or_error.has_value()) {
                        result.warning_or_error = result.tag_failures.back();
                    }
                }
#endif

                nlohmann::ordered_json entries = nlohmann::ordered_json::array();
                if (!tag_failed) {
                    try {
                        phase = "entries";
                        const int dep_index_bits =
                            deps.empty() ? 0 : index_bits(static_cast<int>(deps.size()));
                        int entry_count = 0;

                        while (br.bit_position() + 2 <= record_end_bit) {
                            const std::uint32_t op = br.read_bits(2);
                            if (op == 0) {
                                break;
                            }

                            const std::string key = read_pair_vec_string(br, ctx, pair_vec_remap);
                            nlohmann::ordered_json entry = nlohmann::ordered_json::object();
                            entry["__op"] = op;

                            switch (op) {
                                case 1:
                                    entry[key] = nullptr;
                                    break;
                                case 2:
                                    entry[key] = decode_node(
                                        br, ctx, pair_vec_remap, value_string_remap, out_stats,
                                        &override_state, key
                                    );
                                    break;
                                case 3: {
                                    const std::string ref =
                                        read_pair_vec_string(br, ctx, pair_vec_remap);
                                    entry[key] = nlohmann::ordered_json::object({{"ref", ref}});
                                    break;
                                }
                                default:
                                    break;
                            }

                            if (!deps.empty()) {
                                phase = "dep_entries";
                                nlohmann::ordered_json dep_entries =
                                    nlohmann::ordered_json::array();
                                while (br.bit_position() + 2 <= record_end_bit) {
                                    const std::uint32_t dep_op = br.read_bits(2);
                                    if (dep_op == 0) {
                                        break;
                                    }

                                    const std::string dep_key =
                                        read_pair_vec_string(br, ctx, pair_vec_remap);
                                    const std::uint32_t dep_index =
                                        dep_index_bits > 0 ? br.read_bits(dep_index_bits) : 0u;
                                    const std::uint32_t dep_table_id =
                                        dep_index < deps.size()
                                            ? deps[static_cast<std::size_t>(dep_index)]
                                            : 0u;
                                    const std::string dep_table_name =
                                        dep_table_id < decomp.strings.size()
                                            ? decomp.strings[static_cast<std::size_t>(dep_table_id)]
                                            : std::string{};

                                    nlohmann::ordered_json dep_entry =
                                        nlohmann::ordered_json::object();
                                    dep_entry["__op"] = dep_op;
                                    dep_entry["depTableName"] = dep_table_name;
                                    dep_entry["depTableId"] = dep_table_id;
                                    dep_entry["depIndex"] = dep_index;

                                    switch (dep_op) {
                                        case 1:
                                            dep_entry[dep_key] = nullptr;
                                            break;
                                        case 2:
                                            dep_entry[dep_key] = decode_node(
                                                br, ctx, pair_vec_remap, value_string_remap,
                                                out_stats, &override_state, dep_key
                                            );
                                            break;
                                        case 3: {
                                            const std::string ref =
                                                read_pair_vec_string(br, ctx, pair_vec_remap);
                                            dep_entry[dep_key] =
                                                nlohmann::ordered_json::object({{"ref", ref}});
                                            break;
                                        }
                                        default:
                                            break;
                                    }

                                    dep_entries.push_back(dep_entry);

                                    if (dep_op != 1 && dep_op != 2 && dep_op != 3) {
                                        break;
                                    }
                                }

                                if (!dep_entries.empty()) {
                                    entry["__dep_entries"] = dep_entries;
                                }
                                phase = "entries";
                            }

                            entries.push_back(entry);
                            entry_count++;
                            if (trace_progress && (entry_count % 10000) == 0) {
                                BL4_LOG_INFO(
                                    "    entries=%d bit=%d", entry_count, br.bit_position()
                                );
                            }
                            if (trace_progress && br.bit_position() > record_end_bit) {
                                BL4_LOG_INFO(
                                    "    record overrun: bit=%d end=%d (entry=%d)",
                                    br.bit_position(), record_end_bit, entry_count
                                );
                                break;
                            }
                            if (op != 1 && op != 2 && op != 3) {
                                break;
                            }
                        }
                        if (trace_progress && record_index == 0) {
                            BL4_LOG_INFO(
                                "    entries_end count=%d bit=%d", entry_count, br.bit_position()
                            );
                        }
                    } catch (const std::exception& ex) {
                        if (!result.warning_or_error.has_value()) {
                            std::string msg = "Decode failed";
                            msg += " file='";
                            msg += file_label;
                            msg += "' table='";
                            msg += name;
                            msg += "' record=";
                            msg += std::to_string(record_index);
                            msg += " phase=";
                            msg += phase;
                            msg += " bitPos=";
                            msg += std::to_string(br.bit_position());
                            msg += ": ";
                            msg += ex.what();
                            result.warning_or_error = std::move(msg);
                        }
                    }
                }

                record["entries"] = entries;

                try {
                    if (br.bit_position() < record_end_bit) {
                        const int tail_bits = record_end_bit - br.bit_position();
                        if (options.collect_record_tails) {
                            const auto tail_bytes = read_bits_to_packed_bytes(br, tail_bits);
                            nlohmann::ordered_json tail_obj = nlohmann::ordered_json::object();
                            tail_obj["bitCount"] = tail_bits;
                            tail_obj["hex"] = bytes_to_hex(tail_bytes);
                            record_tails[std::to_string(record_index)] = std::move(tail_obj);
                        } else {
                            br.skip_bits(tail_bits);
                        }
                    } else if (br.bit_position() > record_end_bit) {
                        br.seek(record_end_bit);
                    }
                } catch (const std::exception& ex) {
                    if (!result.warning_or_error.has_value()) {
                        std::string msg = "Decode failed";
                        msg += " file='";
                        msg += file_label;
                        msg += "' table='";
                        msg += name;
                        msg += "' record=";
                        msg += std::to_string(record_index);
                        msg += " bitPos=";
                        msg += std::to_string(br.bit_position());
                        msg += ": ";
                        msg += ex.what();
                        result.warning_or_error = std::move(msg);
                    }
                    override_state.record_end_bit = -1;
                    break;
                }

                override_state.record_end_bit = -1;
                records.push_back(record);
                record_index++;
                total_records++;
            }

            table_obj["records"] = records;
            result.tables[name] = table_obj;
            if (options.collect_record_tails && !record_tails.empty()) {
                result.record_tails[name] = std::move(record_tails);
            }
            if (options.collect_record_tags && !record_tags.empty()) {
                result.record_tags[name] = std::move(record_tags);
            }
            (void)table_start_bit;
            current_record_index = -1;
        }
    } catch (const std::exception& ex) {
        if (!result.warning_or_error.has_value()) {
            std::string msg = "Decode failed";
            msg += " file='";
            msg += file_label;
            msg += "'";
            if (last_table_count > 0) {
                const std::size_t last_idx =
                    (last_table_cursor + last_tables.size() - 1) % last_tables.size();
                const auto& t = last_tables[last_idx];
                msg += " lastTable='";
                msg += t.name;
                msg += "' lastTableStartBit=";
                msg += std::to_string(t.start_bit);
            }
            if (current_record_index >= 0) {
                msg += " record=";
                msg += std::to_string(current_record_index);
            }
            msg += " phase=";
            msg += phase;
            msg += " bitPos=";
            msg += std::to_string(br.bit_position());
            msg += ": ";
            msg += ex.what();
            result.warning_or_error = std::move(msg);
        }
    }

    if (options.collect_data_tail_hex) {
        const auto data = type_code_table.data_span();
        std::size_t tail_start_byte = 0;
        if (last_table_terminator_end_bit >= 0) {
            tail_start_byte = static_cast<std::size_t>(last_table_terminator_end_bit / 8);
            if (tail_start_byte > data.size()) {
                tail_start_byte = data.size();
            }
        } else {
            tail_start_byte = data.size();
        }
        result.data_tail_hex = bytes_to_hex(data.subspan(tail_start_byte));
    }

    if (options.collect_type_flag_overrides && !type_flag_overrides.empty()) {
        std::vector<std::uint32_t> keys;
        keys.reserve(type_flag_overrides.size());
        for (const auto& kv : type_flag_overrides) {
            keys.push_back(kv.first);
        }
        std::sort(keys.begin(), keys.end());
        nlohmann::ordered_json overrides = nlohmann::ordered_json::object();
        for (const auto& k : keys) {
            overrides[std::to_string(k)] = type_flag_overrides[k];
        }
        result.type_flag_overrides = std::move(overrides);
    }

    return result;
}

}  // namespace bl4::ncs
