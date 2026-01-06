/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#include "fs_utils.h"

#include "log.h"

#include <cstdio>
#include <array>
#include <algorithm>
#include <fstream>
#include <string>

#if defined(_WIN32)
#  include <windows.h>
#else
#  include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace bl4::fs_utils {
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

  void ensure_dir(const fs::path &dir) {
    if (dir.empty()) {
      return;
    }
    std::error_code error_code;
    fs::create_directories(dir, error_code);
    if (error_code) {
      BL4_LOG_ERROR("Failed to create directory: %s (%s)", dir.string().c_str(), error_code.message().c_str());
    }
  }

  std::string display_path(const fs::path &path, const fs::path &base_dir) {
    if (base_dir.empty()) {
      return path.string();
    }

    std::error_code error_code;
    fs::path abs_base = fs::weakly_canonical(base_dir, error_code);
    if (error_code) {
      abs_base = base_dir;
      error_code.clear();
    }

    fs::path abs_path = fs::weakly_canonical(path, error_code);
    if (error_code) {
      abs_path = path;
      error_code.clear();
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
}
