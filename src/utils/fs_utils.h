/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#pragma once

#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace bl4::fs_utils {
  std::filesystem::path executable_dir();
  void ensure_dir(const std::filesystem::path &dir);
  std::string display_path(const std::filesystem::path &path, const std::filesystem::path &base_dir);
}
