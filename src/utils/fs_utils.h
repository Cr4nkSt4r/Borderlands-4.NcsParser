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
bool is_metadata_json(const std::filesystem::path& path);
std::vector<std::filesystem::path> collect_inputs(const std::filesystem::path& root);
std::vector<std::uint8_t> read_file(const std::filesystem::path& path);
void write_text_file(const std::filesystem::path& path, const std::string& text);
void write_file(const std::filesystem::path& path, std::span<const std::uint8_t> bytes);
void ensure_dir(const std::filesystem::path& dir);
std::string display_path(const std::filesystem::path& path, const std::filesystem::path& base_dir);
}  // namespace bl4::fs_utils
