/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <vector>

namespace bl4::ncs {
  enum class OodleLZ_Compressor : int {
    Invalid = -1,
    None = 3,
    Kraken = 8,
    Mermaid = 9,
    Selkie = 11,
    Hydra = 12,
    Leviathan = 13,
  };

  enum class OodleLZ_CompressionLevel : int {
    None = 0,
    SuperFast = 1,
    VeryFast = 2,
    Fast = 3,
    Normal = 4,
    Optimal1 = 5,
    Optimal2 = 6,
    Optimal3 = 7,
    Optimal4 = 8,
    Optimal5 = 9,
  };

  class OodleApi {
  public:
    static std::filesystem::path default_library_path();
    static std::unique_ptr<OodleApi> try_load_default();
    static std::unique_ptr<OodleApi> load(const std::filesystem::path &lib_path);

    ~OodleApi();

    void decompress(std::span<const std::uint8_t> compressed, std::span<std::uint8_t> decompressed);
    std::vector<std::uint8_t> compress(std::span<const std::uint8_t> raw, OodleLZ_Compressor compressor, OodleLZ_CompressionLevel level);
    OodleLZ_Compressor get_all_chunks_compressor(std::span<const std::uint8_t> compressed_chunk, std::size_t raw_len);

  private:
    OodleApi(void *handle,
      void *decompress_fn,
      void *compress_fn,
      void *get_comp_buf_size_fn,
      void *get_default_options_fn,
      void *get_config_values_fn,
      void *set_config_values_fn,
      void *get_all_chunks_compressor_fn);

    void ensure_compat_config();

    void *handle_ = nullptr;
    void *decompress_fn_ = nullptr;
    void *compress_fn_ = nullptr;
    void *get_comp_buf_size_fn_ = nullptr;
    void *get_default_options_fn_ = nullptr;
    void *get_config_values_fn_ = nullptr;
    void *set_config_values_fn_ = nullptr;
    void *get_all_chunks_compressor_fn_ = nullptr;
    bool compat_config_initialized_ = false;
  };
}
