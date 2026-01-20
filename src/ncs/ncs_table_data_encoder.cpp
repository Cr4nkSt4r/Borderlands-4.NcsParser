/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#include "ncs_table_data_encoder.h"

#include "ncs_bit_writer.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace bl4::ncs {
namespace {

struct StringPool;

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

int bits_needed(std::uint32_t v) {
    int bits = 0;
    do {
        bits++;
        v >>= 1;
    } while (v != 0);
    return bits;
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

bool equals_none(const std::string& s) {
    if (s.size() != 4) {
        return false;
    }
    return (s[0] == 'n' || s[0] == 'N') && (s[1] == 'o' || s[1] == 'O')
           && (s[2] == 'n' || s[2] == 'N') && (s[3] == 'e' || s[3] == 'E');
}

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

bool split_leaf_type_and_value_known(
    const std::string& s,
    const StringPool* kinds,
    std::string& type_name,
    std::string& value_str
);

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

const nlohmann::ordered_json& unwrap_typeflags_value(const nlohmann::ordered_json& node) {
    const nlohmann::ordered_json* cur = &node;
    while (cur->is_object() && cur->contains("__typeFlags") && cur->contains("value")) {
        cur = &cur->at("value");
    }
    return *cur;
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

bool kind_compatible_with_json(int kind, const nlohmann::ordered_json& actual) {
    switch (kind) {
        case 0:
            return actual.is_null();
        case 1: {
            if (actual.is_string()) {
                return true;
            }
            if (actual.is_object() && count_non_meta_keys(actual) == 1) {
                std::string key;
                const nlohmann::ordered_json* inner = nullptr;
                if (first_non_meta_kv(actual, key, inner) && inner != nullptr) {
                    const nlohmann::ordered_json* inner_actual = &unwrap_typeflags_value(*inner);
                    if (!inner_actual->is_object()) {
                        return true;
                    }
                }
            }
            return false;
        }
        case 2: {
            if (actual.is_array()) {
                return true;
            }
            if (actual.is_object() && count_non_meta_keys(actual) == 1) {
                std::string key;
                const nlohmann::ordered_json* inner = nullptr;
                if (first_non_meta_kv(actual, key, inner) && inner != nullptr) {
                    const nlohmann::ordered_json* inner_actual = &unwrap_typeflags_value(*inner);
                    if (inner_actual->is_array()) {
                        return true;
                    }
                }
            }
            return false;
        }
        case 3:
            return actual.is_object();
        default:
            return false;
    }
}

std::uint32_t
compute_node_type_mask(const nlohmann::ordered_json& node, const StringPool* kinds_pool) {
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
        split_leaf_type_and_value_known(
            actual.get<std::string>(), kinds_pool, value_type, value_str
        );
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
    const std::vector<std::uint32_t>& row_flags,
    const StringPool* kinds_pool
) {
    const auto& actual = unwrap_typeflags_value(node);
    if (&actual != &node) {
        return compute_expected_mask(actual, parent_key, row_flags, kinds_pool);
    }
    if (actual.is_object() && count_non_meta_keys(actual) == 1) {
        std::string key;
        const nlohmann::ordered_json* inner = nullptr;
        if (first_non_meta_kv(actual, key, inner) && inner != nullptr) {
            if (!inner->is_object() && !equals_none(key)) {
                const std::uint32_t want_mask = compute_node_type_mask(*inner, kinds_pool) | 0x80u;
                for (const auto& f : row_flags) {
                    if (f == want_mask) {
                        return want_mask;
                    }
                }
            }
        }
    }

    std::uint32_t mask = compute_node_type_mask(actual, kinds_pool);
    return mask;
}

struct FixedWidthIntArray24 {
    int count = 0;
    int value_bit_width = 0;
    std::vector<int> values;

    int index_bit_width() const { return count > 0 ? index_bits(count) : 0; }
    bool is_active() const {
        return count > 0 && value_bit_width > 0 && static_cast<int>(values.size()) == count;
    }
};

FixedWidthIntArray24 parse_remap(const nlohmann::ordered_json& j) {
    FixedWidthIntArray24 out{};
    if (!j.is_object()) {
        return out;
    }
    if (j.contains("count")) {
        out.count = static_cast<int>(j.at("count").get<std::int64_t>());
    }
    if (j.contains("valueBitWidth")) {
        out.value_bit_width = static_cast<int>(j.at("valueBitWidth").get<std::int64_t>());
    }
    if (j.contains("values") && j.at("values").is_array()) {
        for (const auto& v : j.at("values")) {
            if (v.is_number_integer() || v.is_number_unsigned()) {
                out.values.push_back(static_cast<int>(v.get<std::int64_t>()));
            }
        }
    }
    if (out.count <= 0) {
        out.values.clear();
        out.count = 0;
        out.value_bit_width = 0;
    } else if (static_cast<int>(out.values.size()) != out.count) {
        out.count = static_cast<int>(out.values.size());
    }
    return out;
}

void write_fixed_width_int_array24(BitWriter& bw, const FixedWidthIntArray24& r) {
    bw.write_bits(static_cast<std::uint32_t>(r.count), 24);
    bw.write_bits(static_cast<std::uint32_t>(r.value_bit_width), 8);
    if (r.count <= 0 || r.value_bit_width <= 0) {
        return;
    }
    for (int i = 0; i < r.count; i++) {
        const std::uint32_t v = static_cast<std::uint32_t>(r.values[static_cast<std::size_t>(i)]);
        bw.write_bits(v, r.value_bit_width);
    }
}

int hex_nibble(char c) {
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

std::vector<std::uint8_t> parse_hex_bytes(std::string_view s) {
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

void write_packed_bits(BitWriter& bw, std::span<const std::uint8_t> packed, int bit_count) {
    if (bit_count <= 0) {
        return;
    }
    const int need_bytes = (bit_count + 7) / 8;
    if (static_cast<int>(packed.size()) < need_bytes) {
        throw std::runtime_error("Packed bits buffer too small for bitCount.");
    }

    int written = 0;
    while (written < bit_count) {
        const int chunk = std::min(32, bit_count - written);
        std::uint32_t v = 0;
        for (int i = 0; i < chunk; i++) {
            const int bit_pos = written + i;
            const std::uint8_t b = packed[static_cast<std::size_t>(bit_pos >> 3)];
            const std::uint32_t bit = (b >> (bit_pos & 7)) & 1u;
            v |= bit << i;
        }
        bw.write_bits(v, chunk);
        written += chunk;
    }
}

struct StringPool {
    std::vector<std::string>& list;
    std::unordered_map<std::string, int> index;
    bool allow_growth = true;

    int ensure(const std::string& value) {
        auto it = index.find(value);
        if (it != index.end()) {
            return it->second;
        }
        if (!allow_growth) {
            throw std::runtime_error("String missing from table: " + value);
        }
        const int id = static_cast<int>(list.size());
        list.push_back(value);
        index.emplace(value, id);
        return id;
    }

    int get(const std::string& value) const {
        auto it = index.find(value);
        return it == index.end() ? -1 : it->second;
    }
};

bool split_leaf_type_and_value_known(
    const std::string& s,
    const StringPool* kinds,
    std::string& type_name,
    std::string& value_str
) {
    const std::size_t pos = s.find('\'');
    if (pos == std::string::npos || s.empty() || s.back() != '\'' || pos == 0
        || pos >= s.size() - 1) {
        type_name.clear();
        value_str = s;
        return false;
    }
    const std::string candidate = s.substr(0, pos);
    if (kinds && kinds->get(candidate) >= 0) {
        type_name = candidate;
        value_str = s.substr(pos + 1, s.size() - pos - 2);
        return true;
    }
    type_name.clear();
    value_str = s;
    return false;
}

struct EncodeContext {
    std::vector<std::uint32_t> row_flags;
    int type_index_bits = 0;
    StringPool* value_strings = nullptr;
    int value_index_bits = 0;
    StringPool* value_kinds = nullptr;
    int value_kind_index_bits = 0;
    StringPool* key_strings = nullptr;
    int key_index_bits = 0;
};

void build_row_flags(const TypeCodeBodyHeader& header, std::vector<std::uint32_t>& out) {
    out.assign(header.type_index_count, 0u);
    const std::string& type_codes = header.type_codes;
    for (std::size_t row = 0; row < header.matrix_row_masks.size(); row++) {
        const std::uint64_t row_mask_cols = header.matrix_row_masks[row];
        std::uint32_t flags = 0;
        for (std::size_t col = 0; col < type_codes.size(); col++) {
            if (((row_mask_cols >> col) & 1u) == 0) {
                continue;
            }
            int bit_index = -1;
            if (!try_get_global_type_bit(type_codes[col], bit_index)) {
                continue;
            }
            flags |= (1u << bit_index);
        }
        if (row < out.size()) {
            out[row] = flags;
        }
    }
}

int select_type_index_by_mask(const std::vector<std::uint32_t>& row_flags, std::uint32_t mask) {
    for (std::size_t i = 0; i < row_flags.size(); i++) {
        if (row_flags[i] == mask) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

int map_actual_to_raw(const FixedWidthIntArray24& remap, int actual_index) {
    if (!remap.is_active()) {
        return actual_index;
    }
    for (int i = 0; i < remap.count; i++) {
        if (remap.values[static_cast<std::size_t>(i)] == actual_index) {
            return i;
        }
    }
    return -1;
}

int get_none_index(const StringPool& pool) {
    int idx = pool.get(std::string(""));
    if (idx >= 0) {
        return idx;
    }
    idx = pool.get(std::string("none"));
    if (idx >= 0) {
        return idx;
    }
    return 0;
}

void scan_leaf_string(const std::string& s, StringPool& value_strings, StringPool& value_kinds) {
    std::string type_name;
    std::string value_str;
    split_leaf_type_and_value_known(s, &value_kinds, type_name, value_str);
    value_strings.ensure(value_str);
    value_kinds.ensure(type_name);
}

void scan_variant_node(
    const nlohmann::ordered_json& node,
    StringPool& value_strings,
    StringPool& value_kinds,
    StringPool& key_strings
) {
    const nlohmann::ordered_json& actual = unwrap_typeflags_value(node);
    std::optional<std::uint32_t> override_flags;
    if (node.is_object() && node.contains("__typeFlags") && node.contains("value")) {
        const auto& tf = node.at("__typeFlags");
        if (tf.is_number_integer() || tf.is_number_unsigned()) {
            override_flags = static_cast<std::uint32_t>(tf.get<std::uint64_t>());
        }
    }
    if (override_flags) {
        const int override_kind = static_cast<int>(*override_flags & 3u);
        if (!kind_compatible_with_json(override_kind, actual)) {
            override_flags.reset();
        }
    }

    if (override_flags) {
        const int kind = static_cast<int>(*override_flags & 3u);
        const bool has_self_key = kind == 3 || (*override_flags & 0x80u) != 0u;

        std::string self_key;
        const nlohmann::ordered_json* value_node = &actual;
        const nlohmann::ordered_json* map_node = nullptr;

        if (kind != 3) {
            if (actual.is_object() && count_non_meta_keys(actual) == 1) {
                std::string key;
                const nlohmann::ordered_json* inner = nullptr;
                if (first_non_meta_kv(actual, key, inner) && inner != nullptr) {
                    const nlohmann::ordered_json* inner_actual = &unwrap_typeflags_value(*inner);
                    if (!inner_actual->is_object() && !equals_none(key)) {
                        self_key = key;
                        value_node = inner_actual;
                    }
                }
            }
        } else {
            if (actual.is_object()) {
                const auto non_meta = count_non_meta_keys(actual);
                if (non_meta == 1) {
                    std::string key;
                    const nlohmann::ordered_json* inner = nullptr;
                    if (first_non_meta_kv(actual, key, inner) && inner != nullptr) {
                        const nlohmann::ordered_json* inner_actual =
                            &unwrap_typeflags_value(*inner);
                        const bool inner_is_wrapper = inner->is_object()
                                                      && inner->contains("__typeFlags")
                                                      && inner->contains("value");
                        if (inner_actual->is_object() && !equals_none(key) && !inner_is_wrapper) {
                            self_key = key;
                            map_node = inner_actual;
                        }
                    }
                    if (!map_node) {
                        map_node = &actual;
                    }
                } else {
                    map_node = &actual;
                }
            }
        }

        if (has_self_key && !self_key.empty()) {
            key_strings.ensure(self_key);
        }

        switch (kind) {
            case 0:
                return;
            case 1: {
                const nlohmann::ordered_json& leaf = unwrap_typeflags_value(*value_node);
                if (leaf.is_string()) {
                    scan_leaf_string(leaf.get<std::string>(), value_strings, value_kinds);
                }
                return;
            }
            case 2: {
                const nlohmann::ordered_json& arr = unwrap_typeflags_value(*value_node);
                if (arr.is_array()) {
                    for (const auto& el : arr) {
                        scan_variant_node(el, value_strings, value_kinds, key_strings);
                    }
                }
                return;
            }
            case 3: {
                if (map_node && map_node->is_object()) {
                    const nlohmann::ordered_json& map_actual = unwrap_typeflags_value(*map_node);
                    for (const auto& kv : map_actual.items()) {
                        if (is_meta_key(kv.key())) {
                            continue;
                        }
                        key_strings.ensure(kv.key());
                        scan_variant_node(kv.value(), value_strings, value_kinds, key_strings);
                    }
                }
                return;
            }
            default:
                return;
        }
    }

    if (actual.is_string()) {
        scan_leaf_string(actual.get<std::string>(), value_strings, value_kinds);
        return;
    }
    if (actual.is_array()) {
        for (const auto& el : actual) {
            scan_variant_node(el, value_strings, value_kinds, key_strings);
        }
        return;
    }
    if (actual.is_object()) {
        if (count_non_meta_keys(actual) == 1) {
            std::string key;
            const nlohmann::ordered_json* inner = nullptr;
            if (first_non_meta_kv(actual, key, inner) && inner != nullptr) {
                if (!inner->is_object() && !equals_none(key)) {
                    key_strings.ensure(key);
                    scan_variant_node(*inner, value_strings, value_kinds, key_strings);
                    return;
                }
            }
        }
        for (const auto& kv : actual.items()) {
            if (is_meta_key(kv.key())) {
                continue;
            }
            key_strings.ensure(kv.key());
            scan_variant_node(kv.value(), value_strings, value_kinds, key_strings);
        }
    }
}

void scan_entry(
    const nlohmann::ordered_json& entry,
    StringPool& value_strings,
    StringPool& value_kinds,
    StringPool& key_strings
) {
    if (!entry.is_object()) {
        return;
    }
    int op = 0;
    if (entry.contains("__op")) {
        op = entry.at("__op").get<int>();
    } else if (entry.contains("op")) {
        op = entry.at("op").get<int>();
    }
    std::string key;
    for (const auto& kv : entry.items()) {
        if (is_meta_key(kv.key())) {
            continue;
        }
        key = kv.key();
        break;
    }
    if (!key.empty()) {
        key_strings.ensure(key);
    }
    if (!key.empty() && op == 2 && entry.contains(key)) {
        scan_variant_node(entry.at(key), value_strings, value_kinds, key_strings);
    } else if (!key.empty() && op == 3 && entry.contains(key)) {
        const auto& v = entry.at(key);
        if (v.is_object() && v.contains("ref") && v.at("ref").is_string()) {
            key_strings.ensure(v.at("ref").get<std::string>());
        } else if (v.is_string()) {
            key_strings.ensure(v.get<std::string>());
        }
    }

    if (entry.contains("__dep_entries") && entry.at("__dep_entries").is_array()) {
        for (const auto& dep_entry : entry.at("__dep_entries")) {
            if (!dep_entry.is_object()) {
                continue;
            }
            int dep_op = 0;
            if (dep_entry.contains("__op")) {
                dep_op = dep_entry.at("__op").get<int>();
            } else if (dep_entry.contains("op")) {
                dep_op = dep_entry.at("op").get<int>();
            }
            std::string dep_key;
            for (const auto& kv : dep_entry.items()) {
                if (is_meta_key(kv.key())) {
                    continue;
                }
                if (kv.key() == "depTableName" || kv.key() == "depTableId"
                    || kv.key() == "depIndex") {
                    continue;
                }
                dep_key = kv.key();
                break;
            }
            if (!dep_key.empty()) {
                key_strings.ensure(dep_key);
            }
            if (!dep_key.empty() && dep_op == 2 && dep_entry.contains(dep_key)) {
                scan_variant_node(dep_entry.at(dep_key), value_strings, value_kinds, key_strings);
            } else if (!dep_key.empty() && dep_op == 3 && dep_entry.contains(dep_key)) {
                const auto& v = dep_entry.at(dep_key);
                if (v.is_object() && v.contains("ref") && v.at("ref").is_string()) {
                    key_strings.ensure(v.at("ref").get<std::string>());
                } else if (v.is_string()) {
                    key_strings.ensure(v.get<std::string>());
                }
            }
        }
    }
}

void scan_entry_value_only(
    const nlohmann::ordered_json& entry,
    StringPool& value_strings,
    StringPool& value_kinds,
    StringPool& key_strings
) {
    if (!entry.is_object()) {
        return;
    }
    int op = 0;
    if (entry.contains("__op")) {
        op = entry.at("__op").get<int>();
    } else if (entry.contains("op")) {
        op = entry.at("op").get<int>();
    }
    std::string key;
    for (const auto& kv : entry.items()) {
        if (is_meta_key(kv.key())) {
            continue;
        }
        key = kv.key();
        break;
    }
    if (!key.empty()) {
        key_strings.ensure(key);
    }
    if (!key.empty() && op == 2 && entry.contains(key)) {
        scan_variant_node(entry.at(key), value_strings, value_kinds, key_strings);
    } else if (!key.empty() && op == 3 && entry.contains(key)) {
        const auto& v = entry.at(key);
        if (v.is_object() && v.contains("ref") && v.at("ref").is_string()) {
            key_strings.ensure(v.at("ref").get<std::string>());
        } else if (v.is_string()) {
            key_strings.ensure(v.get<std::string>());
        }
    }
}

void scan_dep_entry(
    const nlohmann::ordered_json& dep_entry,
    StringPool& value_strings,
    StringPool& value_kinds,
    StringPool& key_strings
) {
    if (!dep_entry.is_object()) {
        return;
    }
    int dep_op = 0;
    if (dep_entry.contains("__op")) {
        dep_op = dep_entry.at("__op").get<int>();
    } else if (dep_entry.contains("op")) {
        dep_op = dep_entry.at("op").get<int>();
    }
    std::string dep_key;
    for (const auto& kv : dep_entry.items()) {
        if (is_meta_key(kv.key())) {
            continue;
        }
        if (kv.key() == "depTableName" || kv.key() == "depTableId" || kv.key() == "depIndex") {
            continue;
        }
        dep_key = kv.key();
        break;
    }
    if (!dep_key.empty()) {
        key_strings.ensure(dep_key);
    }
    if (!dep_key.empty() && dep_op == 2 && dep_entry.contains(dep_key)) {
        scan_variant_node(dep_entry.at(dep_key), value_strings, value_kinds, key_strings);
    } else if (!dep_key.empty() && dep_op == 3 && dep_entry.contains(dep_key)) {
        const auto& v = dep_entry.at(dep_key);
        if (v.is_object() && v.contains("ref") && v.at("ref").is_string()) {
            key_strings.ensure(v.at("ref").get<std::string>());
        } else if (v.is_string()) {
            key_strings.ensure(v.get<std::string>());
        }
    }
}

void scan_entry_dep_entries_only(
    const nlohmann::ordered_json& entry,
    StringPool& value_strings,
    StringPool& value_kinds,
    StringPool& key_strings
) {
    if (!entry.is_object()) {
        return;
    }
    if (entry.contains("__dep_entries") && entry.at("__dep_entries").is_array()) {
        for (const auto& dep_entry : entry.at("__dep_entries")) {
            scan_dep_entry(dep_entry, value_strings, value_kinds, key_strings);
        }
    }
}

std::string get_entry_key_raw(const nlohmann::ordered_json& entry) {
    if (!entry.is_object()) {
        return {};
    }
    for (const auto& kv : entry.items()) {
        if (is_meta_key(kv.key())) {
            continue;
        }
        return kv.key();
    }
    return {};
}

std::string to_lower_ascii_copy(const std::string& input) {
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

void scan_tags(
    const nlohmann::ordered_json& tags,
    StringPool& value_strings,
    StringPool& value_kinds,
    StringPool& key_strings
);

void rebuild_value_strings_by_entry_key(
    const nlohmann::ordered_json& tables,
    const nlohmann::json& metadata,
    StringPool& value_strings,
    StringPool& value_kinds,
    StringPool& key_strings
) {
    const nlohmann::json* record_tags =
        metadata.contains("recordTags") ? &metadata.at("recordTags") : nullptr;

    for (const auto& table_kv : tables.items()) {
        if (is_meta_key(table_kv.key())) {
            continue;
        }
        const std::string& table_name = table_kv.key();
        const nlohmann::ordered_json& table_obj = table_kv.value();

        if (!table_obj.is_object() || !table_obj.contains("records")
            || !table_obj.at("records").is_array()) {
            continue;
        }

        const auto& records = table_obj.at("records");
        std::vector<std::size_t> record_order(records.size());
        for (std::size_t i = 0; i < records.size(); ++i) {
            record_order[i] = i;
        }
        std::vector<std::string> record_tag_a(records.size());
        std::vector<uint32_t> record_tag_b(records.size(), 0);
        std::vector<float> record_tag_c(records.size(), 0.0f);
        std::vector<bool> record_tag_b_present(records.size(), false);
        std::vector<bool> record_tag_c_present(records.size(), false);

        if (record_tags && record_tags->is_object()) {
            auto tag_it = record_tags->find(table_name);
            if (tag_it != record_tags->end() && tag_it->is_object()) {
                for (std::size_t rec_idx = 0; rec_idx < records.size(); ++rec_idx) {
                    const std::string rec_key = std::to_string(rec_idx);
                    auto rec_it = tag_it->find(rec_key);
                    if (rec_it != tag_it->end() && rec_it->is_array()) {
                        const auto& tags = *rec_it;
                        for (const auto& tag_obj : tags) {
                            if (!tag_obj.is_object()) {
                                continue;
                            }
                            auto tag_id_it = tag_obj.find("__tag");
                            if (tag_id_it != tag_obj.end() && tag_id_it->is_string()
                                && tag_id_it->get<std::string>() == "a") {
                                auto pair_it = tag_obj.find("pair");
                                if (pair_it != tag_obj.end() && pair_it->is_string()) {
                                    record_tag_a[rec_idx] =
                                        to_lower_ascii_copy(pair_it->get<std::string>());
                                }
                                continue;
                            }
                            if (tag_id_it != tag_obj.end() && tag_id_it->is_string()
                                && tag_id_it->get<std::string>() == "b") {
                                auto u32_it = tag_obj.find("u32");
                                if (u32_it != tag_obj.end() && u32_it->is_number_unsigned()) {
                                    record_tag_b[rec_idx] = u32_it->get<uint32_t>();
                                    record_tag_b_present[rec_idx] = true;
                                }
                                continue;
                            }
                            if (tag_id_it != tag_obj.end() && tag_id_it->is_string()
                                && tag_id_it->get<std::string>() == "c") {
                                auto f32_it = tag_obj.find("f32");
                                if (f32_it != tag_obj.end() && f32_it->is_number_float()) {
                                    record_tag_c[rec_idx] = f32_it->get<float>();
                                    record_tag_c_present[rec_idx] = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        bool has_tag_sort = false;
        for (std::size_t rec_idx = 0; rec_idx < records.size(); ++rec_idx) {
            if (!record_tag_a[rec_idx].empty() || record_tag_b_present[rec_idx]
                || record_tag_c_present[rec_idx]) {
                has_tag_sort = true;
                break;
            }
        }
        if (has_tag_sort) {
            std::stable_sort(
                record_order.begin(), record_order.end(), [&](std::size_t a, std::size_t b) {
                    const auto& a_key = record_tag_a[a];
                    const auto& b_key = record_tag_a[b];
                    if (a_key != b_key) {
                        return a_key > b_key;
                    }
                    const std::uint32_t a_b = record_tag_b_present[a] ? record_tag_b[a] : 0u;
                    const std::uint32_t b_b = record_tag_b_present[b] ? record_tag_b[b] : 0u;
                    if (a_b != b_b) {
                        return a_b > b_b;
                    }
                    const float a_c = record_tag_c_present[a] ? record_tag_c[a] : 0.0f;
                    const float b_c = record_tag_c_present[b] ? record_tag_c[b] : 0.0f;
                    if (a_c != b_c) {
                        return a_c > b_c;
                    }
                    return a > b;
                }
            );
        }

        if (record_tags && record_tags->is_object()) {
            auto tag_it = record_tags->find(table_name);
            if (tag_it != record_tags->end() && tag_it->is_object()) {
                for (std::size_t order_idx = 0; order_idx < record_order.size(); ++order_idx) {
                    const std::size_t rec_idx = record_order[order_idx];
                    const std::string rec_key = std::to_string(rec_idx);
                    auto rec_it = tag_it->find(rec_key);
                    if (rec_it != tag_it->end()) {
                        scan_tags(*rec_it, value_strings, value_kinds, key_strings);
                    }
                }
            }
        }
        struct EntryRef {
            std::size_t record_index;
            std::size_t entry_index;
            std::string key_lower;
        };

        std::vector<EntryRef> entries;
        entries.reserve(1024);
        for (std::size_t order_idx = 0; order_idx < record_order.size(); ++order_idx) {
            const std::size_t rec_idx = record_order[order_idx];
            const auto& record = records[rec_idx];
            if (!record.is_object() || !record.contains("entries")
                || !record.at("entries").is_array()) {
                continue;
            }
            const auto& entry_list = record.at("entries");
            for (std::size_t ent_idx = 0; ent_idx < entry_list.size(); ++ent_idx) {
                const auto& entry = entry_list[ent_idx];
                if (!entry.is_object()) {
                    continue;
                }
                std::string key = get_entry_key_raw(entry);
                std::string key_lower = to_lower_ascii_copy(key);
                entries.push_back({rec_idx, ent_idx, std::move(key_lower)});
            }
        }

        std::stable_sort(entries.begin(), entries.end(), [](const EntryRef& a, const EntryRef& b) {
            if (a.key_lower != b.key_lower) {
                if (a.key_lower.empty()) {
                    return false;
                }
                if (b.key_lower.empty()) {
                    return true;
                }
                return a.key_lower < b.key_lower;
            }
            return false;
        });

        std::size_t group_start = 0;
        while (group_start < entries.size()) {
            std::size_t group_end = group_start + 1;
            while (group_end < entries.size()
                   && entries[group_end].key_lower == entries[group_start].key_lower) {
                ++group_end;
            }

            // entry values first (record/entry order preserved by stable_sort).
            for (std::size_t idx = group_start; idx < group_end; ++idx) {
                const auto& ref = entries[idx];
                const auto& record = records[ref.record_index];
                if (!record.is_object() || !record.contains("entries")
                    || !record.at("entries").is_array()) {
                    continue;
                }
                const auto& entry_list = record.at("entries");
                if (ref.entry_index >= entry_list.size()) {
                    continue;
                }
                const auto& entry = entry_list[ref.entry_index];
                if (!entry.is_object()) {
                    continue;
                }
                scan_entry_value_only(entry, value_strings, value_kinds, key_strings);
            }

            // dep entries ordered by dep key (case-insensitive), except for the audio_event
            // table/file.
            const bool keep_dep_order = to_lower_ascii_copy(table_name) == "audio_event";
            if (keep_dep_order) {
                for (std::size_t idx = group_start; idx < group_end; ++idx) {
                    const auto& ref = entries[idx];
                    const auto& record = records[ref.record_index];
                    if (!record.is_object() || !record.contains("entries")
                        || !record.at("entries").is_array()) {
                        continue;
                    }
                    const auto& entry_list = record.at("entries");
                    if (ref.entry_index >= entry_list.size()) {
                        continue;
                    }
                    const auto& entry = entry_list[ref.entry_index];
                    if (!entry.is_object()) {
                        continue;
                    }
                    if (!entry.contains("__dep_entries") || !entry.at("__dep_entries").is_array()) {
                        continue;
                    }
                    const auto& deps = entry.at("__dep_entries");
                    for (const auto& dep_entry : deps) {
                        scan_dep_entry(dep_entry, value_strings, value_kinds, key_strings);
                    }
                }
            } else {
                struct DepRef {
                    std::size_t record_index;
                    std::size_t entry_index;
                    std::size_t dep_index;
                    std::string key_lower;
                };
                std::vector<DepRef> dep_entries;
                for (std::size_t idx = group_start; idx < group_end; ++idx) {
                    const auto& ref = entries[idx];
                    const auto& record = records[ref.record_index];
                    if (!record.is_object() || !record.contains("entries")
                        || !record.at("entries").is_array()) {
                        continue;
                    }
                    const auto& entry_list = record.at("entries");
                    if (ref.entry_index >= entry_list.size()) {
                        continue;
                    }
                    const auto& entry = entry_list[ref.entry_index];
                    if (!entry.is_object()) {
                        continue;
                    }
                    if (entry.contains("__dep_entries") && entry.at("__dep_entries").is_array()) {
                        const auto& deps = entry.at("__dep_entries");
                        for (std::size_t dep_idx = 0; dep_idx < deps.size(); ++dep_idx) {
                            const auto& dep_entry = deps[dep_idx];
                            if (!dep_entry.is_object()) {
                                continue;
                            }
                            std::string dep_key;
                            for (const auto& kv : dep_entry.items()) {
                                if (is_meta_key(kv.key())) {
                                    continue;
                                }
                                if (kv.key() == "depTableName" || kv.key() == "depTableId"
                                    || kv.key() == "depIndex") {
                                    continue;
                                }
                                dep_key = kv.key();
                                break;
                            }
                            if (dep_key.empty()) {
                                continue;
                            }
                            dep_entries.push_back(
                                {ref.record_index, ref.entry_index, dep_idx,
                                 to_lower_ascii_copy(dep_key)}
                            );
                        }
                    }
                }

                std::stable_sort(
                    dep_entries.begin(), dep_entries.end(), [](const DepRef& a, const DepRef& b) {
                        if (a.key_lower != b.key_lower) {
                            if (a.key_lower.empty()) {
                                return false;
                            }
                            if (b.key_lower.empty()) {
                                return true;
                            }
                            return a.key_lower < b.key_lower;
                        }
                        return false;
                    }
                );

                for (const auto& dep_ref : dep_entries) {
                    const auto& record = records[dep_ref.record_index];
                    if (!record.is_object() || !record.contains("entries")
                        || !record.at("entries").is_array()) {
                        continue;
                    }
                    const auto& entry_list = record.at("entries");
                    if (dep_ref.entry_index >= entry_list.size()) {
                        continue;
                    }
                    const auto& entry = entry_list[dep_ref.entry_index];
                    if (!entry.is_object()) {
                        continue;
                    }
                    if (!entry.contains("__dep_entries") || !entry.at("__dep_entries").is_array()) {
                        continue;
                    }
                    const auto& deps = entry.at("__dep_entries");
                    if (dep_ref.dep_index >= deps.size()) {
                        continue;
                    }
                    scan_dep_entry(
                        deps[dep_ref.dep_index], value_strings, value_kinds, key_strings
                    );
                }
            }

            group_start = group_end;
        }
    }
}

void scan_tags(
    const nlohmann::ordered_json& tags,
    StringPool& value_strings,
    StringPool& value_kinds,
    StringPool& key_strings
) {
    if (!tags.is_array()) {
        return;
    }
    for (const auto& tag_obj : tags) {
        if (!tag_obj.is_object()) {
            continue;
        }
        if (tag_obj.contains("pair") && tag_obj.at("pair").is_string()) {
            key_strings.ensure(tag_obj.at("pair").get<std::string>());
        }
        if (tag_obj.contains("list") && tag_obj.at("list").is_array()) {
            for (const auto& v : tag_obj.at("list")) {
                if (v.is_string()) {
                    key_strings.ensure(v.get<std::string>());
                }
            }
        }
        if (tag_obj.contains("variant")) {
            scan_variant_node(tag_obj.at("variant"), value_strings, value_kinds, key_strings);
        }
    }
}

void collect_used_indices_node(
    const nlohmann::ordered_json& node,
    const StringPool& value_strings,
    const StringPool& value_kinds,
    const StringPool& key_strings,
    std::unordered_set<int>& value_indices,
    std::unordered_set<int>& key_indices
) {
    const nlohmann::ordered_json& actual = unwrap_typeflags_value(node);
    std::optional<std::uint32_t> override_flags;
    if (node.is_object() && node.contains("__typeFlags") && node.contains("value")) {
        const auto& tf = node.at("__typeFlags");
        if (tf.is_number_integer() || tf.is_number_unsigned()) {
            override_flags = static_cast<std::uint32_t>(tf.get<std::uint64_t>());
        }
    }
    if (override_flags) {
        const int override_kind = static_cast<int>(*override_flags & 3u);
        if (!kind_compatible_with_json(override_kind, actual)) {
            override_flags.reset();
        }
    }

    if (override_flags) {
        const int kind = static_cast<int>(*override_flags & 3u);
        const bool has_self_key = kind == 3 || (*override_flags & 0x80u) != 0u;

        std::string self_key;
        const nlohmann::ordered_json* value_node = &actual;
        const nlohmann::ordered_json* map_node = nullptr;

        if (kind != 3) {
            if (actual.is_object() && count_non_meta_keys(actual) == 1) {
                std::string key;
                const nlohmann::ordered_json* inner = nullptr;
                if (first_non_meta_kv(actual, key, inner) && inner != nullptr) {
                    const nlohmann::ordered_json* inner_actual = &unwrap_typeflags_value(*inner);
                    if (!inner_actual->is_object() && !equals_none(key)) {
                        self_key = key;
                        value_node = inner_actual;
                    }
                }
            }
        } else {
            if (actual.is_object()) {
                const auto non_meta = count_non_meta_keys(actual);
                if (non_meta == 1) {
                    std::string key;
                    const nlohmann::ordered_json* inner = nullptr;
                    if (first_non_meta_kv(actual, key, inner) && inner != nullptr) {
                        const nlohmann::ordered_json* inner_actual =
                            &unwrap_typeflags_value(*inner);
                        const bool inner_is_wrapper = inner->is_object()
                                                      && inner->contains("__typeFlags")
                                                      && inner->contains("value");
                        if (inner_actual->is_object() && !equals_none(key) && !inner_is_wrapper) {
                            self_key = key;
                            map_node = inner_actual;
                        }
                    }
                    if (!map_node) {
                        map_node = &actual;
                    }
                } else {
                    map_node = &actual;
                }
            }
        }

        if (has_self_key && !self_key.empty()) {
            const int ki = key_strings.get(self_key);
            if (ki < 0) {
                throw std::runtime_error("Key string missing from table: " + self_key);
            }
            key_indices.insert(ki);
        }

        switch (kind) {
            case 0:
                return;
            case 1: {
                const nlohmann::ordered_json& leaf = unwrap_typeflags_value(*value_node);
                if (leaf.is_string()) {
                    std::string type_name;
                    std::string value_str;
                    split_leaf_type_and_value_known(
                        leaf.get<std::string>(), &value_kinds, type_name, value_str
                    );
                    const int vi = value_strings.get(value_str);
                    if (vi < 0) {
                        throw std::runtime_error("Value string missing from table: " + value_str);
                    }
                    value_indices.insert(vi);
                    const int ki = value_kinds.get(type_name);
                    if (ki < 0) {
                        throw std::runtime_error("Value kind missing from table: " + type_name);
                    }
                }
                return;
            }
            case 2: {
                const nlohmann::ordered_json& arr = unwrap_typeflags_value(*value_node);
                if (arr.is_array()) {
                    for (const auto& el : arr) {
                        collect_used_indices_node(
                            el, value_strings, value_kinds, key_strings, value_indices, key_indices
                        );
                    }
                }
                return;
            }
            case 3: {
                if (map_node && map_node->is_object()) {
                    const nlohmann::ordered_json& map_actual = unwrap_typeflags_value(*map_node);
                    for (const auto& kv : map_actual.items()) {
                        if (is_meta_key(kv.key())) {
                            continue;
                        }
                        const int ki = key_strings.get(kv.key());
                        if (ki < 0) {
                            throw std::runtime_error("Key string missing from table: " + kv.key());
                        }
                        key_indices.insert(ki);
                        collect_used_indices_node(
                            kv.value(), value_strings, value_kinds, key_strings, value_indices,
                            key_indices
                        );
                    }
                }
                return;
            }
            default:
                return;
        }
    }

    if (actual.is_string()) {
        std::string type_name;
        std::string value_str;
        split_leaf_type_and_value_known(
            actual.get<std::string>(), &value_kinds, type_name, value_str
        );
        const int vi = value_strings.get(value_str);
        if (vi < 0) {
            throw std::runtime_error("Value string missing from table: " + value_str);
        }
        value_indices.insert(vi);
        const int ki = value_kinds.get(type_name);
        if (ki < 0) {
            throw std::runtime_error("Value kind missing from table: " + type_name);
        }
        return;
    }
    if (actual.is_array()) {
        for (const auto& el : actual) {
            collect_used_indices_node(
                el, value_strings, value_kinds, key_strings, value_indices, key_indices
            );
        }
        return;
    }
    if (actual.is_object()) {
        if (count_non_meta_keys(actual) == 1) {
            std::string key;
            const nlohmann::ordered_json* inner = nullptr;
            if (first_non_meta_kv(actual, key, inner) && inner != nullptr) {
                if (!inner->is_object() && !equals_none(key)) {
                    const int ki = key_strings.get(key);
                    if (ki < 0) {
                        throw std::runtime_error("Key string missing from table: " + key);
                    }
                    key_indices.insert(ki);
                    collect_used_indices_node(
                        *inner, value_strings, value_kinds, key_strings, value_indices, key_indices
                    );
                    return;
                }
            }
        }
        for (const auto& kv : actual.items()) {
            if (is_meta_key(kv.key())) {
                continue;
            }
            const int ki = key_strings.get(kv.key());
            if (ki < 0) {
                throw std::runtime_error("Key string missing from table: " + kv.key());
            }
            key_indices.insert(ki);
            collect_used_indices_node(
                kv.value(), value_strings, value_kinds, key_strings, value_indices, key_indices
            );
        }
    }
}

void collect_used_indices_entry(
    const nlohmann::ordered_json& entry,
    const StringPool& value_strings,
    const StringPool& value_kinds,
    const StringPool& key_strings,
    std::unordered_set<int>& value_indices,
    std::unordered_set<int>& key_indices
) {
    if (!entry.is_object()) {
        return;
    }
    int op = 0;
    if (entry.contains("__op")) {
        op = entry.at("__op").get<int>();
    } else if (entry.contains("op")) {
        op = entry.at("op").get<int>();
    }
    std::string key;
    for (const auto& kv : entry.items()) {
        if (is_meta_key(kv.key())) {
            continue;
        }
        key = kv.key();
        break;
    }
    if (!key.empty()) {
        const int ki = key_strings.get(key);
        if (ki < 0) {
            throw std::runtime_error("Key string missing from table: " + key);
        }
        key_indices.insert(ki);
    }
    if (!key.empty() && op == 2 && entry.contains(key)) {
        collect_used_indices_node(
            entry.at(key), value_strings, value_kinds, key_strings, value_indices, key_indices
        );
    } else if (!key.empty() && op == 3 && entry.contains(key)) {
        const auto& v = entry.at(key);
        if (v.is_object() && v.contains("ref") && v.at("ref").is_string()) {
            const std::string ref = v.at("ref").get<std::string>();
            const int ki = key_strings.get(ref);
            if (ki < 0) {
                throw std::runtime_error("Key string missing from table: " + ref);
            }
            key_indices.insert(ki);
        } else if (v.is_string()) {
            const std::string ref = v.get<std::string>();
            const int ki = key_strings.get(ref);
            if (ki < 0) {
                throw std::runtime_error("Key string missing from table: " + ref);
            }
            key_indices.insert(ki);
        }
    }

    if (entry.contains("__dep_entries") && entry.at("__dep_entries").is_array()) {
        for (const auto& dep_entry : entry.at("__dep_entries")) {
            if (!dep_entry.is_object()) {
                continue;
            }
            int dep_op = 0;
            if (dep_entry.contains("__op")) {
                dep_op = dep_entry.at("__op").get<int>();
            } else if (dep_entry.contains("op")) {
                dep_op = dep_entry.at("op").get<int>();
            }
            std::string dep_key;
            for (const auto& kv : dep_entry.items()) {
                if (is_meta_key(kv.key())) {
                    continue;
                }
                if (kv.key() == "depTableName" || kv.key() == "depTableId"
                    || kv.key() == "depIndex") {
                    continue;
                }
                dep_key = kv.key();
                break;
            }
            if (!dep_key.empty()) {
                const int ki = key_strings.get(dep_key);
                if (ki < 0) {
                    throw std::runtime_error("Key string missing from table: " + dep_key);
                }
                key_indices.insert(ki);
            }
            if (!dep_key.empty() && dep_op == 2 && dep_entry.contains(dep_key)) {
                collect_used_indices_node(
                    dep_entry.at(dep_key), value_strings, value_kinds, key_strings, value_indices,
                    key_indices
                );
            } else if (!dep_key.empty() && dep_op == 3 && dep_entry.contains(dep_key)) {
                const auto& v = dep_entry.at(dep_key);
                if (v.is_object() && v.contains("ref") && v.at("ref").is_string()) {
                    const std::string ref = v.at("ref").get<std::string>();
                    const int ki = key_strings.get(ref);
                    if (ki < 0) {
                        throw std::runtime_error("Key string missing from table: " + ref);
                    }
                    key_indices.insert(ki);
                } else if (v.is_string()) {
                    const std::string ref = v.get<std::string>();
                    const int ki = key_strings.get(ref);
                    if (ki < 0) {
                        throw std::runtime_error("Key string missing from table: " + ref);
                    }
                    key_indices.insert(ki);
                }
            }
        }
    }
}

void collect_used_indices_tags(
    const nlohmann::ordered_json& tags,
    const StringPool& value_strings,
    const StringPool& value_kinds,
    const StringPool& key_strings,
    std::unordered_set<int>& value_indices,
    std::unordered_set<int>& key_indices
) {
    if (!tags.is_array()) {
        return;
    }
    for (const auto& tag_obj : tags) {
        if (!tag_obj.is_object()) {
            continue;
        }
        if (tag_obj.contains("pair") && tag_obj.at("pair").is_string()) {
            const std::string key = tag_obj.at("pair").get<std::string>();
            const int ki = key_strings.get(key);
            if (ki < 0) {
                throw std::runtime_error("Key string missing from table: " + key);
            }
            key_indices.insert(ki);
        }
        if (tag_obj.contains("list") && tag_obj.at("list").is_array()) {
            for (const auto& v : tag_obj.at("list")) {
                if (!v.is_string()) {
                    continue;
                }
                const std::string key = v.get<std::string>();
                const int ki = key_strings.get(key);
                if (ki < 0) {
                    throw std::runtime_error("Key string missing from table: " + key);
                }
                key_indices.insert(ki);
            }
        }
        if (tag_obj.contains("variant")) {
            collect_used_indices_node(
                tag_obj.at("variant"), value_strings, value_kinds, key_strings, value_indices,
                key_indices
            );
        }
    }
}

void write_pair_vec_string(
    BitWriter& bw,
    const std::string& value,
    EncodeContext& ctx,
    const FixedWidthIntArray24* pair_vec_remap,
    const std::vector<int>* pair_actual_to_raw,
    std::string_view context
) {
    int actual_index = ctx.key_strings->get(value);
    if (actual_index < 0) {
        if (value.empty() || equals_none(value)) {
            actual_index = get_none_index(*ctx.key_strings);
        } else {
            throw std::runtime_error(
                "Key string missing from table: " + value + " (ctx=" + std::string(context) + ")"
            );
        }
    }
    int raw_index = actual_index;
    int raw_bits = ctx.key_index_bits;
    if (pair_vec_remap && pair_vec_remap->is_active()) {
        if (pair_actual_to_raw && actual_index >= 0
            && actual_index < static_cast<int>(pair_actual_to_raw->size())) {
            const int mapped = (*pair_actual_to_raw)[static_cast<std::size_t>(actual_index)];
            if (mapped >= 0) {
                raw_index = mapped;
            } else {
                raw_index = map_actual_to_raw(*pair_vec_remap, actual_index);
            }
        } else {
            raw_index = map_actual_to_raw(*pair_vec_remap, actual_index);
        }
        raw_bits = pair_vec_remap->index_bit_width();
        if (raw_index < 0) {
            throw std::runtime_error(
                "PairVec remap missing index for key: " + value + " (ctx=" + std::string(context)
                + ")"
            );
        }
    }
    bw.write_bits(static_cast<std::uint32_t>(raw_index), raw_bits);
}

void write_value(
    BitWriter& bw,
    const std::string& value,
    EncodeContext& ctx,
    const FixedWidthIntArray24* value_remap,
    const std::vector<int>* value_actual_to_raw
) {
    std::string type_name;
    std::string value_str;
    split_leaf_type_and_value_known(value, ctx.value_kinds, type_name, value_str);

    const int value_index = ctx.value_strings->get(value_str);
    if (value_index < 0) {
        throw std::runtime_error("Value string missing from table: " + value_str);
    }
    const int kind_index = ctx.value_kinds->get(type_name);
    if (kind_index < 0) {
        throw std::runtime_error("Value kind missing from table: " + type_name);
    }

    int raw_index = value_index;
    int raw_bits = ctx.value_index_bits;
    if (value_remap && value_remap->is_active()) {
        if (value_actual_to_raw && value_index >= 0
            && value_index < static_cast<int>(value_actual_to_raw->size())) {
            const int mapped = (*value_actual_to_raw)[static_cast<std::size_t>(value_index)];
            if (mapped >= 0) {
                raw_index = mapped;
            } else {
                raw_index = map_actual_to_raw(*value_remap, value_index);
            }
        } else {
            raw_index = map_actual_to_raw(*value_remap, value_index);
        }
        raw_bits = value_remap->index_bit_width();
        if (raw_index < 0) {
            throw std::runtime_error("Value remap missing index for value: " + value_str);
        }
    }

    bw.write_bits(static_cast<std::uint32_t>(raw_index), raw_bits);
    bw.write_bits(static_cast<std::uint32_t>(kind_index), ctx.value_kind_index_bits);
}

struct EncodeState {
    EncodeContext ctx{};
    const FixedWidthIntArray24* pair_vec_remap = nullptr;
    const FixedWidthIntArray24* value_remap = nullptr;
    const std::vector<int>* pair_actual_to_raw = nullptr;
    const std::vector<int>* value_actual_to_raw = nullptr;
    const std::unordered_map<std::uint32_t, std::uint32_t>* overrides = nullptr;
    std::uint32_t* node_index = nullptr;
};

void encode_node(
    BitWriter& bw,
    const nlohmann::ordered_json& node,
    EncodeState& st,
    std::string_view parent_key
) {
    std::uint32_t node_index = 0;
    if (st.node_index) {
        node_index = (*st.node_index)++;
    }

    std::optional<std::uint32_t> override_flags;
    if (node.is_object() && node.contains("__typeFlags") && node.contains("value")) {
        const auto& tf = node.at("__typeFlags");
        if (tf.is_number_integer() || tf.is_number_unsigned()) {
            override_flags = static_cast<std::uint32_t>(tf.get<std::uint64_t>());
        }
    }
    const nlohmann::ordered_json& unwrapped = unwrap_typeflags_value(node);
    const nlohmann::ordered_json* actual = &unwrapped;
    if (!override_flags && st.overrides) {
        auto it = st.overrides->find(node_index);
        if (it != st.overrides->end()) {
            override_flags = it->second;
        }
    }
    if (override_flags) {
        const int override_kind = static_cast<int>(*override_flags & 3u);
        if (!kind_compatible_with_json(override_kind, *actual)) {
            override_flags.reset();
        }
    }

    std::uint32_t flags =
        override_flags.has_value()
            ? *override_flags
            : compute_expected_mask(*actual, parent_key, st.ctx.row_flags, st.ctx.value_kinds);

    const int kind = static_cast<int>(flags & 3u);
    int type_index = select_type_index_by_mask(st.ctx.row_flags, flags);
    if (type_index < 0) {
        const std::uint32_t want_kind = static_cast<std::uint32_t>(kind & 3);
        const bool want_self = (flags & 0x80u) != 0u;
        int fallback = -1;
        for (std::size_t i = 0; i < st.ctx.row_flags.size(); i++) {
            const auto f = st.ctx.row_flags[i];
            if ((f & 3u) != want_kind) {
                continue;
            }
            if (((f & 0x80u) != 0u) == want_self) {
                fallback = static_cast<int>(i);
                break;
            }
            if (fallback < 0) {
                fallback = static_cast<int>(i);
            }
        }
        if (fallback < 0) {
            throw std::runtime_error("No type row for flags mask: " + std::to_string(flags));
        }
        type_index = fallback;
    }

    bw.write_bits(static_cast<std::uint32_t>(type_index), st.ctx.type_index_bits);

    bool has_self_key = kind == 3 || (flags & 0x80u) != 0u;
    std::string self_key;

    const nlohmann::ordered_json* value_node = actual;
    const nlohmann::ordered_json* map_node = nullptr;

    if (kind != 3) {
        if (actual->is_object() && count_non_meta_keys(*actual) == 1) {
            std::string key;
            const nlohmann::ordered_json* inner = nullptr;
            if (first_non_meta_kv(*actual, key, inner) && inner != nullptr) {
                const nlohmann::ordered_json* inner_actual = &unwrap_typeflags_value(*inner);
                if (!inner_actual->is_object() && !equals_none(key)) {
                    self_key = key;
                    value_node = inner_actual;
                }
            }
        }
    } else {
        if (actual->is_object()) {
            const auto non_meta = count_non_meta_keys(*actual);
            if (non_meta == 1) {
                std::string key;
                const nlohmann::ordered_json* inner = nullptr;
                if (first_non_meta_kv(*actual, key, inner) && inner != nullptr) {
                    const nlohmann::ordered_json* inner_actual = &unwrap_typeflags_value(*inner);
                    const bool inner_is_wrapper = inner->is_object()
                                                  && inner->contains("__typeFlags")
                                                  && inner->contains("value");
                    if (inner_actual->is_object() && !equals_none(key) && !inner_is_wrapper) {
                        self_key = key;
                        map_node = inner_actual;
                    }
                }
                if (!map_node) {
                    map_node = actual;
                }
            } else {
                map_node = actual;
            }
        }
    }

    if (has_self_key) {
        if (self_key.empty()) {
            self_key.clear();
        }
        write_pair_vec_string(
            bw, self_key, st.ctx, st.pair_vec_remap, st.pair_actual_to_raw, "self_key"
        );
    }

    switch (kind) {
        case 0:
            break;
        case 1:
            value_node = &unwrap_typeflags_value(*value_node);
            if (!value_node->is_string()) {
                throw std::runtime_error("Expected string leaf value");
            }
            write_value(
                bw, value_node->get<std::string>(), st.ctx, st.value_remap, st.value_actual_to_raw
            );
            break;
        case 2: {
            value_node = &unwrap_typeflags_value(*value_node);
            if (!value_node->is_array()) {
                throw std::runtime_error("Expected array node");
            }
            for (const auto& el : *value_node) {
                bw.write_bits(1, 1);
                encode_node(bw, el, st, std::string_view{});
            }
            bw.write_bits(0, 1);
            break;
        }
        case 3: {
            if (!map_node || !map_node->is_object()) {
                throw std::runtime_error("Expected map node");
            }
            map_node = &unwrap_typeflags_value(*map_node);
            for (const auto& kv : map_node->items()) {
                if (is_meta_key(kv.key())) {
                    continue;
                }
                bw.write_bits(1, 1);
                std::string map_ctx = "map_entry";
                if (!parent_key.empty()) {
                    map_ctx += ":";
                    map_ctx += std::string(parent_key);
                }
                write_pair_vec_string(
                    bw, kv.key(), st.ctx, st.pair_vec_remap, st.pair_actual_to_raw, map_ctx
                );
                encode_node(bw, kv.value(), st, kv.key());
            }
            bw.write_bits(0, 1);
            break;
        }
        default:
            throw std::runtime_error("Unknown node kind");
    }
}

std::uint32_t read_u32_json(const nlohmann::ordered_json& j, std::uint32_t def = 0) {
    if (j.is_number_unsigned()) {
        return j.get<std::uint32_t>();
    }
    if (j.is_number_integer()) {
        return static_cast<std::uint32_t>(j.get<std::int64_t>());
    }
    return def;
}

}  // namespace

TableDataEncodeResult encode_table_data(
    const nlohmann::ordered_json& tables,
    const nlohmann::json& metadata,
    std::vector<std::string>& header_strings,
    std::vector<std::string>& value_strings,
    std::vector<std::string>& value_kinds,
    std::vector<std::string>& key_strings,
    const TypeCodeBodyHeader& type_header,
    std::uint32_t value_strings_declared_count,
    std::uint32_t value_kinds_declared_count,
    std::uint32_t key_strings_declared_count,
    bool allow_header_growth,
    bool allow_value_growth,
    bool allow_kind_growth,
    bool allow_key_growth
) {
    if (!tables.is_object()) {
        throw std::runtime_error("tables root must be an object");
    }

    if (value_strings_declared_count > value_strings.size()) {
        value_strings.reserve(value_strings_declared_count);
    }
    if (value_kinds_declared_count > value_kinds.size()) {
        value_kinds.reserve(value_kinds_declared_count);
    }
    if (key_strings_declared_count > key_strings.size()) {
        key_strings.reserve(key_strings_declared_count);
    }

    StringPool header_pool{header_strings, {}, allow_header_growth};
    StringPool value_pool{value_strings, {}, allow_value_growth};
    StringPool kinds_pool{value_kinds, {}, allow_kind_growth};
    StringPool key_pool{key_strings, {}, allow_key_growth};

    for (std::size_t i = 0; i < header_strings.size(); i++) {
        header_pool.index.emplace(header_strings[i], static_cast<int>(i));
    }
    for (std::size_t i = 0; i < value_strings.size(); i++) {
        value_pool.index.emplace(value_strings[i], static_cast<int>(i));
    }
    for (std::size_t i = 0; i < value_kinds.size(); i++) {
        kinds_pool.index.emplace(value_kinds[i], static_cast<int>(i));
    }
    for (std::size_t i = 0; i < key_strings.size(); i++) {
        key_pool.index.emplace(key_strings[i], static_cast<int>(i));
    }

    if (allow_value_growth && value_strings.empty()) {
        rebuild_value_strings_by_entry_key(tables, metadata, value_pool, kinds_pool, key_pool);
    }

    if (value_strings_declared_count > value_strings.size()) {
        value_pool.index.reserve(static_cast<std::size_t>(value_strings_declared_count) * 2);
    }
    if (value_kinds_declared_count > value_kinds.size()) {
        kinds_pool.index.reserve(static_cast<std::size_t>(value_kinds_declared_count) * 2);
    }
    if (key_strings_declared_count > key_strings.size()) {
        key_pool.index.reserve(static_cast<std::size_t>(key_strings_declared_count) * 2);
    }

    for (const auto& kv : tables.items()) {
        if (is_meta_key(kv.key())) {
            continue;
        }
        header_pool.ensure(kv.key());
        if (kv.value().is_object() && kv.value().contains("__deps")
            && kv.value().at("__deps").is_array()) {
            for (const auto& dep : kv.value().at("__deps")) {
                if (dep.is_string()) {
                    header_pool.ensure(dep.get<std::string>());
                }
            }
        }
        if (!kv.value().is_object()) {
            continue;
        }
        if (kv.value().contains("records") && kv.value().at("records").is_array()) {
            for (const auto& record : kv.value().at("records")) {
                if (!record.is_object()) {
                    continue;
                }
                if (record.contains("entries") && record.at("entries").is_array()) {
                    for (const auto& entry : record.at("entries")) {
                        scan_entry(entry, value_pool, kinds_pool, key_pool);
                    }
                }
            }
        }
    }

    if (metadata.contains("recordTags") && metadata.at("recordTags").is_object()) {
        for (const auto& table_entry : metadata.at("recordTags").items()) {
            const auto& by_record = table_entry.value();
            if (!by_record.is_object()) {
                continue;
            }
            for (const auto& rec_entry : by_record.items()) {
                scan_tags(rec_entry.value(), value_pool, kinds_pool, key_pool);
            }
        }
    }

    if (value_strings.size() > value_strings_declared_count) {
        value_strings_declared_count = static_cast<std::uint32_t>(value_strings.size());
    }
    if (value_kinds.size() > value_kinds_declared_count) {
        value_kinds_declared_count = static_cast<std::uint32_t>(value_kinds.size());
    }
    if (key_strings.size() > key_strings_declared_count) {
        key_strings_declared_count = static_cast<std::uint32_t>(key_strings.size());
    }

    EncodeContext ctx{};
    ctx.type_index_bits = index_bits(static_cast<int>(type_header.type_index_count));
    build_row_flags(type_header, ctx.row_flags);
    ctx.value_strings = &value_pool;
    if (value_strings_declared_count == 0) {
        value_strings_declared_count = static_cast<std::uint32_t>(value_strings.size());
    }
    if (value_kinds_declared_count == 0) {
        value_kinds_declared_count = static_cast<std::uint32_t>(value_kinds.size());
    }
    if (key_strings_declared_count == 0) {
        key_strings_declared_count = static_cast<std::uint32_t>(key_strings.size());
    }
    ctx.value_index_bits = index_bits(static_cast<int>(value_strings_declared_count));
    ctx.value_kinds = &kinds_pool;
    ctx.value_kind_index_bits = index_bits(static_cast<int>(value_kinds_declared_count));
    ctx.key_strings = &key_pool;
    ctx.key_index_bits = index_bits(static_cast<int>(key_strings_declared_count));

    std::unordered_map<std::string, FixedWidthIntArray24> pair_remaps;
    std::unordered_map<std::string, FixedWidthIntArray24> value_remaps;
    if (metadata.contains("tableRemaps") && metadata.at("tableRemaps").is_object()) {
        for (const auto& kv : metadata.at("tableRemaps").items()) {
            if (!kv.value().is_object()) {
                continue;
            }
            if (kv.value().contains("pairVec")) {
                pair_remaps.emplace(kv.key(), parse_remap(kv.value().at("pairVec")));
            }
            if (kv.value().contains("valueStrings")) {
                value_remaps.emplace(kv.key(), parse_remap(kv.value().at("valueStrings")));
            }
        }
    }

    std::unordered_map<std::uint32_t, std::uint32_t> type_flag_overrides;
    if (metadata.contains("typeFlagOverrides") && metadata.at("typeFlagOverrides").is_object()) {
        for (const auto& kv : metadata.at("typeFlagOverrides").items()) {
            std::uint32_t key = 0;
            try {
                key = static_cast<std::uint32_t>(std::stoul(kv.key(), nullptr, 10));
            } catch (...) {
                continue;
            }
            type_flag_overrides.emplace(key, read_u32_json(kv.value()));
        }
    }

    const auto* record_tags =
        metadata.contains("recordTags") ? &metadata.at("recordTags") : nullptr;
    const nlohmann::json* record_tails = nullptr;
    const std::string data_tail_hex{};

    const int table_id_bits = index_bits(static_cast<int>(header_strings.size()));

    BitWriter bw;
    std::uint32_t global_node_index = 0;

    for (const auto& kv : tables.items()) {
        if (is_meta_key(kv.key())) {
            continue;
        }
        const std::string& table_name = kv.key();
        const nlohmann::ordered_json& table_obj = kv.value();
        const int table_id = header_pool.get(table_name);
        if (table_id < 0) {
            throw std::runtime_error("Table name missing in headerStrings: " + table_name);
        }
        bw.write_bits(static_cast<std::uint32_t>(table_id), table_id_bits);

        std::vector<std::uint32_t> deps;
        std::unordered_map<std::string, std::uint32_t> dep_index_by_name;
        if (table_obj.is_object() && table_obj.contains("__deps")
            && table_obj.at("__deps").is_array()) {
            const auto& deps_json = table_obj.at("__deps");
            deps.reserve(deps_json.size());
            for (const auto& dep : deps_json) {
                if (!dep.is_string()) {
                    continue;
                }
                const std::string dep_name = dep.get<std::string>();
                const int dep_id = header_pool.get(dep_name);
                if (dep_id < 0) {
                    throw std::runtime_error("Dep table missing in headerStrings: " + dep_name);
                }
                dep_index_by_name.emplace(dep_name, static_cast<std::uint32_t>(deps.size()));
                deps.push_back(static_cast<std::uint32_t>(dep_id));
            }
        }

        for (const auto dep_id : deps) {
            bw.write_bits(dep_id, table_id_bits);
        }
        bw.write_bits(0, table_id_bits);

        FixedWidthIntArray24 pair_remap{};
        FixedWidthIntArray24 value_remap{};
        if (pair_remaps.find(table_name) != pair_remaps.end()) {
            pair_remap = pair_remaps[table_name];
        }
        if (value_remaps.find(table_name) != value_remaps.end()) {
            value_remap = value_remaps[table_name];
        }

        if (pair_remap.is_active() || value_remap.is_active()) {
            std::unordered_set<int> used_value_indices;
            std::unordered_set<int> used_key_indices;
            if (value_remap.is_active()) {
                const std::size_t reserve_count =
                    value_strings_declared_count > 0
                        ? static_cast<std::size_t>(value_strings_declared_count)
                        : value_strings.size();
                used_value_indices.reserve(reserve_count);
            }
            if (pair_remap.is_active()) {
                const std::size_t reserve_count =
                    key_strings_declared_count > 0
                        ? static_cast<std::size_t>(key_strings_declared_count)
                        : key_strings.size();
                used_key_indices.reserve(reserve_count);
            }
            if (table_obj.is_object() && table_obj.contains("records")
                && table_obj.at("records").is_array()) {
                for (const auto& record : table_obj.at("records")) {
                    if (!record.is_object()) {
                        continue;
                    }
                    if (record.contains("entries") && record.at("entries").is_array()) {
                        for (const auto& entry : record.at("entries")) {
                            collect_used_indices_entry(
                                entry, value_pool, kinds_pool, key_pool, used_value_indices,
                                used_key_indices
                            );
                        }
                    }
                }
            }
            if (record_tags && record_tags->is_object() && record_tags->contains(table_name)) {
                const auto& by_record = record_tags->at(table_name);
                if (by_record.is_object()) {
                    for (const auto& rec_entry : by_record.items()) {
                        collect_used_indices_tags(
                            rec_entry.value(), value_pool, kinds_pool, key_pool, used_value_indices,
                            used_key_indices
                        );
                    }
                }
            }

            (void)used_key_indices;
            (void)used_value_indices;
        }

        write_fixed_width_int_array24(bw, pair_remap);
        write_fixed_width_int_array24(bw, value_remap);

        bw.align_to_byte();

        std::vector<int> pair_actual_to_raw;
        std::vector<int> value_actual_to_raw;
        if (pair_remap.is_active()) {
            const std::size_t size_hint = key_strings_declared_count > 0
                                              ? static_cast<std::size_t>(key_strings_declared_count)
                                              : key_strings.size();
            pair_actual_to_raw.assign(size_hint, -1);
            for (int raw = 0; raw < pair_remap.count; raw++) {
                const int actual = pair_remap.values[static_cast<std::size_t>(raw)];
                if (actual >= 0 && static_cast<std::size_t>(actual) < pair_actual_to_raw.size()) {
                    auto& slot = pair_actual_to_raw[static_cast<std::size_t>(actual)];
                    if (slot < 0) {
                        slot = raw;
                    }
                }
            }
        }
        if (value_remap.is_active()) {
            const std::size_t size_hint =
                value_strings_declared_count > 0
                    ? static_cast<std::size_t>(value_strings_declared_count)
                    : value_strings.size();
            value_actual_to_raw.assign(size_hint, -1);
            for (int raw = 0; raw < value_remap.count; raw++) {
                const int actual = value_remap.values[static_cast<std::size_t>(raw)];
                if (actual >= 0 && static_cast<std::size_t>(actual) < value_actual_to_raw.size()) {
                    auto& slot = value_actual_to_raw[static_cast<std::size_t>(actual)];
                    if (slot < 0) {
                        slot = raw;
                    }
                }
            }
        }

        EncodeState st{};
        st.ctx = ctx;
        st.pair_vec_remap = pair_remap.is_active() ? &pair_remap : nullptr;
        st.value_remap = value_remap.is_active() ? &value_remap : nullptr;
        st.pair_actual_to_raw = pair_remap.is_active() ? &pair_actual_to_raw : nullptr;
        st.value_actual_to_raw = value_remap.is_active() ? &value_actual_to_raw : nullptr;
        st.overrides = nullptr;
        st.node_index = &global_node_index;

        nlohmann::json empty_tags = nlohmann::json::array();
        const nlohmann::json* tags_table = nullptr;
        const nlohmann::json* tails_table = nullptr;
        if (record_tags && record_tags->is_object() && record_tags->contains(table_name)) {
            tags_table = &record_tags->at(table_name);
        }
        if (record_tails && record_tails->is_object() && record_tails->contains(table_name)) {
            tails_table = &record_tails->at(table_name);
        }

        if (table_obj.is_object() && table_obj.contains("records")
            && table_obj.at("records").is_array()) {
            int record_index = 0;
            for (const auto& record : table_obj.at("records")) {
                BitWriter rec_bw;

                const nlohmann::json* tags = nullptr;
                if (tags_table && tags_table->is_object()
                    && tags_table->contains(std::to_string(record_index))) {
                    tags = &tags_table->at(std::to_string(record_index));
                }
                if (!tags) {
                    tags = &empty_tags;
                }

                if (tags->is_array()) {
                    for (const auto& tag_obj : *tags) {
                        if (!tag_obj.is_object()) {
                            continue;
                        }
                        if (!tag_obj.contains("__tag") || !tag_obj.at("__tag").is_string()) {
                            continue;
                        }
                        const std::string tag = tag_obj.at("__tag").get<std::string>();
                        if (tag.empty()) {
                            continue;
                        }
                        const char t = tag[0];
                        rec_bw.write_bits(static_cast<std::uint8_t>(t), 8);
                        switch (t) {
                            case 'a': {
                                if (tag_obj.contains("pair") && tag_obj.at("pair").is_string()) {
                                    write_pair_vec_string(
                                        rec_bw, tag_obj.at("pair").get<std::string>(), st.ctx,
                                        st.pair_vec_remap, st.pair_actual_to_raw, "tag_pair"
                                    );
                                }
                                break;
                            }
                            case 'b': {
                                if (tag_obj.contains("u32")) {
                                    const std::uint32_t u = read_u32_json(tag_obj.at("u32"));
                                    rec_bw.write_bits(u, 32);
                                }
                                break;
                            }
                            case 'c': {
                                if (tag_obj.contains("u32")) {
                                    const std::uint32_t u = read_u32_json(tag_obj.at("u32"));
                                    rec_bw.write_bits(u, 32);
                                } else if (tag_obj.contains("f32")
                                           && tag_obj.at("f32").is_number()) {
                                    const float f = tag_obj.at("f32").get<float>();
                                    std::uint32_t u = 0;
                                    std::memcpy(&u, &f, sizeof(float));
                                    rec_bw.write_bits(u, 32);
                                }
                                break;
                            }
                            case 'd':
                            case 'e':
                            case 'f': {
                                if (tag_obj.contains("list") && tag_obj.at("list").is_array()) {
                                    for (const auto& v : tag_obj.at("list")) {
                                        if (v.is_string()) {
                                            write_pair_vec_string(
                                                rec_bw, v.get<std::string>(), st.ctx,
                                                st.pair_vec_remap, st.pair_actual_to_raw, "tag_list"
                                            );
                                        }
                                    }
                                }
                                write_pair_vec_string(
                                    rec_bw, "", st.ctx, st.pair_vec_remap, st.pair_actual_to_raw,
                                    "tag_term"
                                );
                                break;
                            }
                            case 'p': {
                                if (tag_obj.contains("variant")) {
                                    nlohmann::ordered_json variant = tag_obj.at("variant");
                                    encode_node(rec_bw, variant, st, std::string_view{});
                                }
                                break;
                            }
                            default:
                                break;
                        }
                    }
                }

                rec_bw.write_bits(static_cast<std::uint8_t>('z'), 8);

                if (record.is_object() && record.contains("entries")
                    && record.at("entries").is_array()) {
                    const int dep_index_bits =
                        deps.empty() ? 0 : index_bits(static_cast<int>(deps.size()));
                    for (const auto& entry : record.at("entries")) {
                        if (!entry.is_object()) {
                            continue;
                        }
                        int op = 0;
                        if (entry.contains("__op")) {
                            op = entry.at("__op").get<int>();
                        } else if (entry.contains("op")) {
                            op = entry.at("op").get<int>();
                        }
                        if (op <= 0) {
                            continue;
                        }
                        std::string key;
                        for (const auto& kv2 : entry.items()) {
                            if (is_meta_key(kv2.key())) {
                                continue;
                            }
                            key = kv2.key();
                            break;
                        }
                        if (key.empty()) {
                            continue;
                        }
                        rec_bw.write_bits(static_cast<std::uint32_t>(op), 2);
                        write_pair_vec_string(
                            rec_bw, key, st.ctx, st.pair_vec_remap, st.pair_actual_to_raw,
                            "entry_key"
                        );
                        if (op == 1) {
                            // no payload
                        } else if (op == 2 && entry.contains(key)) {
                            encode_node(rec_bw, entry.at(key), st, key);
                        } else if (op == 3 && entry.contains(key)) {
                            const auto& v = entry.at(key);
                            if (v.is_object() && v.contains("ref") && v.at("ref").is_string()) {
                                write_pair_vec_string(
                                    rec_bw, v.at("ref").get<std::string>(), st.ctx,
                                    st.pair_vec_remap, st.pair_actual_to_raw, "entry_ref"
                                );
                            } else if (v.is_string()) {
                                write_pair_vec_string(
                                    rec_bw, v.get<std::string>(), st.ctx, st.pair_vec_remap,
                                    st.pair_actual_to_raw, "entry_ref"
                                );
                            }
                        }

                        if (!deps.empty()) {
                            if (entry.contains("__dep_entries")
                                && entry.at("__dep_entries").is_array()) {
                                for (const auto& dep_entry : entry.at("__dep_entries")) {
                                    if (!dep_entry.is_object()) {
                                        continue;
                                    }
                                    int dep_op = 0;
                                    if (dep_entry.contains("__op")) {
                                        dep_op = dep_entry.at("__op").get<int>();
                                    } else if (dep_entry.contains("op")) {
                                        dep_op = dep_entry.at("op").get<int>();
                                    }
                                    if (dep_op <= 0) {
                                        continue;
                                    }
                                    std::string dep_key;
                                    for (const auto& kv3 : dep_entry.items()) {
                                        if (is_meta_key(kv3.key())) {
                                            continue;
                                        }
                                        if (kv3.key() == "depTableName" || kv3.key() == "depTableId"
                                            || kv3.key() == "depIndex") {
                                            continue;
                                        }
                                        dep_key = kv3.key();
                                        break;
                                    }
                                    if (dep_key.empty()) {
                                        continue;
                                    }
                                    rec_bw.write_bits(static_cast<std::uint32_t>(dep_op), 2);
                                    write_pair_vec_string(
                                        rec_bw, dep_key, st.ctx, st.pair_vec_remap,
                                        st.pair_actual_to_raw, "dep_key"
                                    );

                                    std::uint32_t dep_index = 0;
                                    if (dep_entry.contains("depIndex")) {
                                        dep_index = read_u32_json(dep_entry.at("depIndex"));
                                    } else if (dep_entry.contains("depTableName")
                                               && dep_entry.at("depTableName").is_string()) {
                                        const std::string dep_name =
                                            dep_entry.at("depTableName").get<std::string>();
                                        if (dep_index_by_name.find(dep_name)
                                            != dep_index_by_name.end()) {
                                            dep_index = dep_index_by_name[dep_name];
                                        }
                                    } else if (dep_entry.contains("depTableId")) {
                                        const auto dep_id =
                                            read_u32_json(dep_entry.at("depTableId"));
                                        for (std::size_t di = 0; di < deps.size(); di++) {
                                            if (deps[di] == dep_id) {
                                                dep_index = static_cast<std::uint32_t>(di);
                                                break;
                                            }
                                        }
                                    }
                                    if (dep_index_bits > 0) {
                                        rec_bw.write_bits(dep_index, dep_index_bits);
                                    }

                                    if (dep_op == 1) {
                                        // no payload
                                    } else if (dep_op == 2 && dep_entry.contains(dep_key)) {
                                        encode_node(rec_bw, dep_entry.at(dep_key), st, dep_key);
                                    } else if (dep_op == 3 && dep_entry.contains(dep_key)) {
                                        const auto& dv = dep_entry.at(dep_key);
                                        if (dv.is_object() && dv.contains("ref")
                                            && dv.at("ref").is_string()) {
                                            write_pair_vec_string(
                                                rec_bw, dv.at("ref").get<std::string>(), st.ctx,
                                                st.pair_vec_remap, st.pair_actual_to_raw, "dep_ref"
                                            );
                                        } else if (dv.is_string()) {
                                            write_pair_vec_string(
                                                rec_bw, dv.get<std::string>(), st.ctx,
                                                st.pair_vec_remap, st.pair_actual_to_raw, "dep_ref"
                                            );
                                        }
                                    }
                                }
                            }
                            rec_bw.write_bits(0, 2);
                        }
                    }
                }

                rec_bw.write_bits(0, 2);

                if (tails_table && tails_table->is_object()
                    && tails_table->contains(std::to_string(record_index))) {
                    const auto& tail = tails_table->at(std::to_string(record_index));
                    if (tail.is_object() && tail.contains("bitCount") && tail.contains("hex")) {
                        const int bit_count = static_cast<int>(read_u32_json(tail.at("bitCount")));
                        if (tail.at("hex").is_string()) {
                            const auto bytes = parse_hex_bytes(tail.at("hex").get<std::string>());
                            write_packed_bits(rec_bw, bytes, bit_count);
                        }
                    }
                }

                rec_bw.align_to_byte();

                const std::uint32_t record_len_bytes =
                    4u + static_cast<std::uint32_t>(rec_bw.byte_length());
                bw.write_bits(record_len_bytes, 32);
                const auto rec_bytes = rec_bw.to_bytes();
                bw.write_bytes_aligned(rec_bytes);
                record_index++;
            }
        }

        bw.write_bits(0, 32);
        bw.write_bits(static_cast<std::uint8_t>('z'), 8);
    }

    bw.write_bits(0, table_id_bits);
    bw.align_to_byte();

    TableDataEncodeResult out{};
    out.data_section = bw.to_bytes();
    return out;
}

}  // namespace bl4::ncs
