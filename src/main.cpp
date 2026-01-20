/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#include "ncs_parser.h"
#include "utils/fs_utils.h"
#include "utils/log.h"

#include <chrono>
#include <filesystem>
#include <optional>
#include <string_view>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct Settings {
    bool minimal = false;
    bool keep_dep_entries = false;
    bool keep_strings = false;
    bool write_decomp = false;
    bool debug = false;
    std::optional<fs::path> oodle_path;
};

static void print_usage() {
    BL4_LOG_INFO(
        "Usage:\n" \
        "    ncs_parser <file-or-dir> [--minimal] [--deps] [--strings] [--decomp] [--full] [--oodle <path>] [--debug]\n\n" \
        "Options:\n" \
        "    First argument must be a file or directory\n" \
        "    --minimal     strips metadata from JSON output and skips the table metadata .json generation\n" \
        "    --deps keeps  __dep_entries in .json\n" \
        "    --strings     keeps header/value strings in metadata .json\n" \
        "    --decomp      writes .decomp payloads\n" \
        "    --full        includes --deps --strings --decomp\n" \
        "    --debug       enables extra logging\n"
    );
    BL4_LOG_INFO("[INFO] JSON inputs require a matching <name>_metadata.json file.");
}

static bool is_supported_input(const fs::path& p) {
    const auto ext = p.extension().string();
    return ext == ".ncs" || ext == ".decomp" || ext == ".json";
}

static void strip_helper_fields(nlohmann::ordered_json& j, const Settings& settings) {
    if (j.is_object()) {
        if (j.contains("__typeFlags") && j.contains("value")) {
            nlohmann::ordered_json inner = j["value"];
            strip_helper_fields(inner, settings);
            j = std::move(inner);
            return;
        }
        std::vector<std::string> to_remove;
        for (auto it = j.begin(); it != j.end(); ++it) {
            if (it.key().rfind("__", 0) == 0) {
                if (it.key().rfind("__dep_entries", 0) == 0 && settings.keep_dep_entries) {
                    continue;
                }
                to_remove.push_back(it.key());
            }
        }
        for (const auto& k : to_remove) {
            j.erase(k);
        }
        for (auto& kv : j.items()) {
            strip_helper_fields(kv.value(), settings);
        }
    } else if (j.is_array()) {
        for (auto& el : j) {
            strip_helper_fields(el, settings);
        }
    }
}

static void write_outputs(
    const fs::path& out_json_dir,
    const std::string& base,
    const bl4::ncs::DecodeResult& res,
    const Settings& settings
) {
    auto tables = res.tables;
    auto suffix = std::string("");
    if (settings.minimal) {
        strip_helper_fields(tables, settings);
        suffix = "_minimal";
    }
    const fs::path json_path = out_json_dir / (base + suffix + std::string(".json"));
    bl4::fs_utils::write_text_file(json_path, tables.dump(2));
    BL4_LOG_INFO("Wrote: %s", json_path.string().c_str());

    if (settings.minimal) {
        return;
    }
    if (!res.metadata.is_object() || res.metadata.empty()) {
        return;
    }
    const fs::path meta_path = out_json_dir / (base + std::string("_metadata.json"));
    bl4::fs_utils::write_text_file(meta_path, res.metadata.dump(2));
    BL4_LOG_INFO("Wrote: %s", meta_path.string().c_str());
}

static void write_decomp_output(
    const fs::path& out_decomp_dir,
    const std::string& base,
    const bl4::ncs::DecodeResult& res
) {
    if (res.decomp_payload.empty()) {
        return;
    }
    const fs::path decomp_path = out_decomp_dir / (base + std::string(".decomp"));
    bl4::fs_utils::write_file(decomp_path, res.decomp_payload);
    BL4_LOG_INFO("Wrote: %s", decomp_path.string().c_str());
}

static nlohmann::ordered_json read_json_file(const fs::path& path, bool debug) {
    const auto t0 = std::chrono::steady_clock::now();
    const auto bytes = bl4::fs_utils::read_file(path);
    const auto t1 = std::chrono::steady_clock::now();
    if (bytes.empty()) {
        throw std::runtime_error("JSON file is empty: " + path.string());
    }
    const auto text = std::string(bytes.begin(), bytes.end());
    const auto t2 = std::chrono::steady_clock::now();
    auto json = nlohmann::ordered_json::parse(text);
    const auto t3 = std::chrono::steady_clock::now();
    if (debug) {
        const auto read_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        const auto copy_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
        const auto parse_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count();
        BL4_LOG_INFO(
            "JSON read %s: bytes=%zu read=%lldms copy=%lldms parse=%lldms",
            path.string().c_str(), bytes.size(),
            static_cast<long long>(read_ms),
            static_cast<long long>(copy_ms),
            static_cast<long long>(parse_ms)
        );
    }
    return json;
}

static nlohmann::json read_metadata_file(const fs::path& path, bool debug) {
    const auto t0 = std::chrono::steady_clock::now();
    const auto bytes = bl4::fs_utils::read_file(path);
    const auto t1 = std::chrono::steady_clock::now();
    if (bytes.empty()) {
        throw std::runtime_error("JSON file is empty: " + path.string());
    }
    const auto text = std::string(bytes.begin(), bytes.end());
    const auto t2 = std::chrono::steady_clock::now();
    auto json = nlohmann::json::parse(text);
    const auto t3 = std::chrono::steady_clock::now();
    if (debug) {
        const auto read_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        const auto copy_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
        const auto parse_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count();
        BL4_LOG_INFO(
            "Metadata read %s: bytes=%zu read=%lldms copy=%lldms parse=%lldms",
            path.string().c_str(), bytes.size(),
            static_cast<long long>(read_ms),
            static_cast<long long>(copy_ms),
            static_cast<long long>(parse_ms)
        );
    }
    return json;
}

static void write_encoded_outputs(
    const fs::path& out_ncs_dir,
    const fs::path& out_decomp_dir,
    const std::string& base,
    const bl4::ncs::EncodeResult& res,
    bool write_decomp
) {
    const fs::path ncs_path = out_ncs_dir / (base + std::string(".ncs"));
    bl4::fs_utils::write_file(ncs_path, res.ncs_bytes);
    BL4_LOG_INFO("Wrote: %s", ncs_path.string().c_str());
    if (!write_decomp) {
        return;
    }
    const fs::path decomp_path = out_decomp_dir / (base + std::string(".decomp"));
    bl4::fs_utils::write_file(decomp_path, res.decomp_payload);
    BL4_LOG_INFO("Wrote: %s", decomp_path.string().c_str());
}

static void process_file(const fs::path& path, const fs::path& out_json_dir, const Settings& settings) {
    if (!is_supported_input(path)) {
        BL4_LOG_INFO("Skipped: %s", path.string().c_str());
        return;
    }
    if (bl4::fs_utils::is_metadata_json(path)) {
        BL4_LOG_INFO("Skipped: %s", path.string().c_str());
        return;
    }

    const std::string base = path.stem().string();
    try {
        if (path.extension() == ".ncs") {
            bl4::ncs::ParserDecodeOptions opt{};
            opt.oodle_path = settings.oodle_path;
            opt.keep_strings = settings.keep_strings;
            opt.debug = settings.debug;
            const auto res = bl4::ncs::NcsParser::DecodeNcsFile(path, opt);
            write_outputs(out_json_dir, base, res, settings);
            const fs::path exe_dir = bl4::fs_utils::executable_dir();
            const fs::path out_root = exe_dir / "output";
            if (settings.write_decomp) {
                const fs::path out_decomp_dir = out_root / "decomp";
                bl4::fs_utils::ensure_dir(out_decomp_dir);
                write_decomp_output(out_decomp_dir, base, res);
            }
        } else if (path.extension() == ".decomp") {
            const auto bytes = bl4::fs_utils::read_file(path);
            if (bytes.empty()) {
                BL4_LOG_INFO("Skipped: %s (empty file)", path.string().c_str());
                return;
            }
            bl4::ncs::ParserDecodeOptions opt{};
            opt.oodle_path = settings.oodle_path;
            opt.keep_strings = settings.keep_strings;
            opt.debug = settings.debug;
            const auto res = bl4::ncs::NcsParser::DecodeDecompBytes(bytes, opt, base);
            write_outputs(out_json_dir, base, res, settings);
            if (settings.write_decomp) {
                const fs::path exe_dir = bl4::fs_utils::executable_dir();
                const fs::path out_root = exe_dir / "output";
                const fs::path out_decomp_dir = out_root / "decomp";
                bl4::fs_utils::ensure_dir(out_decomp_dir);
                write_decomp_output(out_decomp_dir, base, res);
            }
        } else if (path.extension() == ".json") {
            const auto tables = read_json_file(path, settings.debug);
            const fs::path meta_path = path.parent_path() / (base + std::string("_metadata.json"));
            if (!fs::exists(meta_path)) {
                throw std::runtime_error("Missing metadata file: " + meta_path.string());
            }
            const auto metadata = read_metadata_file(meta_path, settings.debug);
            bl4::ncs::ParserEncodeOptions opt{};
            opt.oodle_path = settings.oodle_path;
            opt.debug = settings.debug;
            const auto res = bl4::ncs::NcsParser::EncodeJsonToNcs(tables, metadata, opt, base);
            const fs::path exe_dir = bl4::fs_utils::executable_dir();
            const fs::path out_root = exe_dir / "output";
            const fs::path out_ncs_dir = out_root / "ncs";
            const fs::path out_decomp_dir = out_root / "decomp";
            bl4::fs_utils::ensure_dir(out_ncs_dir);
            if (settings.write_decomp) {
                bl4::fs_utils::ensure_dir(out_decomp_dir);
            }
            write_encoded_outputs(out_ncs_dir, out_decomp_dir, base, res, settings.write_decomp);
        }
    } catch (const std::exception& e) {
        BL4_LOG_ERROR("Failed: %s (%s)", path.string().c_str(), e.what());
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    const std::string_view first_arg = argv[1];
    if (!first_arg.empty() && first_arg[0] == '-') {
        BL4_LOG_ERROR("First argument must be a file or folder.");
        print_usage();
        return 2;
    }
    const fs::path input = fs::path(std::string(first_arg));
    Settings settings;
    for (int i = 2; i < argc; i++) {
        const std::string_view arg = argv[i];
        if (arg == "--minimal") {
            settings.minimal = true;
            continue;
        }
        if (arg == "--deps") {
            settings.keep_dep_entries = true;
            continue;
        }
        if (arg == "--strings") {
            settings.keep_strings = true;
            continue;
        }
        if (arg == "--decomp") {
            settings.write_decomp = true;
            continue;
        }
        if (arg == "--full") {
            settings.keep_dep_entries = true;
            settings.keep_strings = true;
            settings.write_decomp = true;
            continue;
        }
        if (arg == "--debug") {
            settings.debug = true;
            continue;
        }
        if (arg == "--oodle") {
            if (i + 1 >= argc) {
                BL4_LOG_ERROR("Missing value for --oodle");
                return 2;
            }
            settings.oodle_path = fs::path(argv[++i]);
            continue;
        }
        BL4_LOG_ERROR("Unknown option: %s", std::string(arg).c_str());
        return 2;
    }

    if (!fs::exists(input)) {
        BL4_LOG_ERROR("Input does not exist: %s", input.string().c_str());
        return 2;
    }

    const fs::path exe_dir = bl4::fs_utils::executable_dir();
    const fs::path out_root = exe_dir / "output";
    const fs::path out_json_dir = out_root / "json";
    bl4::fs_utils::ensure_dir(out_json_dir);

    if (fs::is_directory(input)) {
        const auto inputs = bl4::fs_utils::collect_inputs(input);
        for (const auto& p : inputs) {
            process_file(p, out_json_dir, settings);
        }
        return 0;
    }

    process_file(input, out_json_dir, settings);
    return 0;
}
