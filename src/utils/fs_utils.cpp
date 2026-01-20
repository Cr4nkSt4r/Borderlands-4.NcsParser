/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#include "fs_utils.h"

#include "log.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <fstream>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

bool is_known_ext(const fs::path& p) {
    const auto ext = p.extension().string();
    return ext == ".ncs" || ext == ".decomp" || ext == ".json";
}

static bool ends_with(const std::string& s, const std::string& suffix) {
    if (s.size() < suffix.size()) {
        return false;
    }
    return std::equal(suffix.rbegin(), suffix.rend(), s.rbegin());
}

namespace bl4::fs_utils {
bool is_metadata_json(const fs::path& path) {
    if (path.extension() != ".json") {
        return false;
    }
    return ends_with(path.stem().string(), "_metadata");
}

fs::path executable_dir() {
#if defined(_WIN32)
    std::wstring buf(32768, L'\0');
    const DWORD n = ::GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    if (n == 0 || n >= buf.size()) {
        return {};
    }
    buf.resize(n);
    return fs::path(buf).parent_path();
#else
    std::array<char, 4096> buf{};
    const ssize_t n = ::readlink("/proc/self/exe", buf.data(), buf.size() - 1);
    if (n <= 0) {
        return {};
    }
    buf[static_cast<std::size_t>(n)] = '\0';
    return fs::path(buf.data()).parent_path();
#endif
}

std::vector<fs::path> collect_inputs(const fs::path& root) {
    std::vector<fs::path> out;
    for (const auto& it : fs::recursive_directory_iterator(root)) {
        if (!it.is_regular_file()) {
            continue;
        }
        const auto& p = it.path();
        if (!is_known_ext(p)) {
            continue;
        }
        if (is_metadata_json(p)) {
            continue;
        }
        out.push_back(p);
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<std::uint8_t> read_file(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error(std::string("Failed to open file for reading: ") + path.string());
    }
    f.seekg(0, std::ios::end);
    const auto len = f.tellg();
    f.seekg(0, std::ios::beg);
    if (len < 0) {
        throw std::runtime_error(std::string("Failed to get file size: ") + path.string());
    }
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(len));
    if (!buf.empty()) {
        f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    }
    return buf;
}

void write_text_file(const fs::path& path, const std::string& text) {
    ensure_dir(path.parent_path());
    std::ofstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error(std::string("Failed to open file for writing: ") + path.string());
    }
    f.write(text.data(), static_cast<std::streamsize>(text.size()));
}

void write_file(const fs::path& path, std::span<const std::uint8_t> bytes) {
    ensure_dir(path.parent_path());
    std::ofstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error(std::string("Failed to open file for writing: ") + path.string());
    }
    if (!bytes.empty()) {
        f.write(
            reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())
        );
    }
}

void ensure_dir(const fs::path& dir) {
    if (dir.empty()) {
        return;
    }
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
        BL4_LOG_ERROR(
            "Failed to create directory: %s (%s)", dir.string().c_str(), ec.message().c_str()
        );
    }
}

std::string display_path(const fs::path& path, const fs::path& base_dir) {
    if (base_dir.empty()) {
        return path.string();
    }

    std::error_code ec;
    fs::path abs_base = fs::weakly_canonical(base_dir, ec);
    if (ec) {
        abs_base = base_dir;
        ec.clear();
    }

    fs::path abs_path = fs::weakly_canonical(path, ec);
    if (ec) {
        abs_path = path;
        ec.clear();
    }

    const fs::path rel = abs_path.lexically_relative(abs_base);
    if (rel.empty()) {
        return abs_path.string();
    }
    if (rel == ".") {
        return rel.string();
    }
    const auto it = rel.begin();
    if (it != rel.end() && *it == "..") {
        return abs_path.string();
    }
    return rel.string();
}
}  // namespace bl4::fs_utils
