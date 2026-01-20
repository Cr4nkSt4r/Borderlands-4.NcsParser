/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#include "oodle/oodle_api.h"
#include "utils/log.h"

#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace bl4::ncs {
#if defined(_WIN32)
void* load_library_handle(const fs::path& p) {
    const std::wstring w = p.wstring();
    HMODULE m = ::LoadLibraryW(w.c_str());
    return reinterpret_cast<void*>(m);
}

void unload_library_handle(void* h) {
    if (!h) {
        return;
    }
    ::FreeLibrary(reinterpret_cast<HMODULE>(h));
}

void* get_export(void* h, const char* name) {
    if (!h) {
        return nullptr;
    }
    FARPROC p = ::GetProcAddress(reinterpret_cast<HMODULE>(h), name);
    return reinterpret_cast<void*>(p);
}
#else
void* load_library_handle(const fs::path& p) {
    return ::dlopen(p.string().c_str(), RTLD_NOW);
}

void unload_library_handle(void* h) {
    if (!h) {
        return;
    }
    ::dlclose(h);
}

void* get_export(void* h, const char* name) {
    if (!h) {
        return nullptr;
    }
    return ::dlsym(h, name);
}
#endif

template <typename Fn>
Fn require_export(void* h, const char* name) {
    void* p = get_export(h, name);
    if (!p) {
        throw std::runtime_error(std::string("Missing Oodle export: ") + name);
    }
    return reinterpret_cast<Fn>(p);
}

template <typename Fn>
Fn optional_export(void* h, const char* name) {
    void* p = get_export(h, name);
    return reinterpret_cast<Fn>(p);
}

using OodleLZ_DecompressFn = long (*)(
    const void* compBuf,
    long compBufSize,
    void* rawBuf,
    long rawLen,
    int fuzzSafe,
    int checkCrc,
    int verbosity,
    void* rawBufBase,
    long rawBufSize,
    void* callback,
    void* callbackUser,
    void* decoderMemory,
    long decoderMemorySize,
    int threadPhase
);

using OodleLZ_CompressFn = long (*)(
    int compressor,
    const void* rawBuf,
    long rawLen,
    void* compBuf,
    int level,
    void* options,
    const void* dictionaryBase,
    void* lrm,
    void* scratchMem,
    long scratchSize
);

using OodleLZ_GetCompressedBufferSizeNeededFn = long (*)(int compressor, long rawLen);
using OodleLZ_CompressOptions_GetDefaultFn = void* (*)(int compressor, int level);
using Oodle_GetConfigValuesFn = void (*)(void* configValues);
using Oodle_SetConfigValuesFn = void (*)(void* configValues);
using OodleLZ_GetAllChunksCompressorFn =
    int (*)(const void* compBuf, long compBufSize, long rawLen);

fs::path get_executable_dir() {
#if defined(_WIN32)
    std::wstring buf(32768, L'\0');
    DWORD n = ::GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    if (n == 0 || n >= buf.size()) {
        return fs::path();
    }
    buf.resize(n);
    return fs::path(buf).parent_path();
#else
    std::array<char, 4096> buf{};
    const ssize_t n = ::readlink("/proc/self/exe", buf.data(), buf.size() - 1);
    if (n <= 0) {
        return fs::path();
    }
    buf[static_cast<std::size_t>(n)] = '\0';
    return fs::path(buf.data()).parent_path();
#endif
}

fs::path default_oodle_library_path() {
    const fs::path exedir = get_executable_dir();
#if defined(_WIN32)
    return exedir / "oo2core_9_win64.dll";
#else
#if defined(__aarch64__) || defined(_M_ARM64)
    return exedir / "liboo2corelinuxarm64.so.9";
#else
    return exedir / "liboo2corelinux64.so.9";
#endif
#endif
}

fs::path OodleApi::default_library_path() {
    return default_oodle_library_path();
}

std::unique_ptr<OodleApi> OodleApi::try_load_default() {
    const fs::path cand = default_oodle_library_path();
    std::error_code ec;
    if (!fs::exists(cand, ec) || ec) {
        return nullptr;
    }
    try {
        return OodleApi::load(cand);
    } catch (const std::exception& ex) {
        BL4_LOG_ERROR(
            "Failed to load Oodle from %s: %s", cand.filename().string().c_str(), ex.what()
        );
        return nullptr;
    }
}

std::unique_ptr<OodleApi> OodleApi::load(const fs::path& lib_path) {
    void* h = load_library_handle(lib_path);
    if (!h) {
        throw std::runtime_error(std::string("Failed to load Oodle library: ") + lib_path.string());
    }
    try {
        auto* decompress = require_export<void*>(h, "OodleLZ_Decompress");
        auto* compress = require_export<void*>(h, "OodleLZ_Compress");
        auto* get_size = require_export<void*>(h, "OodleLZ_GetCompressedBufferSizeNeeded");
        auto* get_all_chunks = require_export<void*>(h, "OodleLZ_GetAllChunksCompressor");

        void* get_default_opts = optional_export<void*>(h, "OodleLZ_CompressOptions_GetDefault");
        void* get_cfg = optional_export<void*>(h, "Oodle_GetConfigValues");
        void* set_cfg = optional_export<void*>(h, "Oodle_SetConfigValues");

        return std::unique_ptr<OodleApi>(new OodleApi(
            h, decompress, compress, get_size, get_default_opts, get_cfg, set_cfg, get_all_chunks
        ));
    } catch (...) {
        unload_library_handle(h);
        throw;
    }
}

OodleApi::OodleApi(
    void* handle,
    void* decompress_fn,
    void* compress_fn,
    void* get_comp_buf_size_fn,
    void* get_default_options_fn,
    void* get_config_values_fn,
    void* set_config_values_fn,
    void* get_all_chunks_compressor_fn
)
    : handle_(handle),
      decompress_fn_(decompress_fn),
      compress_fn_(compress_fn),
      get_comp_buf_size_fn_(get_comp_buf_size_fn),
      get_default_options_fn_(get_default_options_fn),
      get_config_values_fn_(get_config_values_fn),
      set_config_values_fn_(set_config_values_fn),
      get_all_chunks_compressor_fn_(get_all_chunks_compressor_fn) {}

OodleApi::~OodleApi() {
    unload_library_handle(handle_);
    handle_ = nullptr;
}

void OodleApi::ensure_compat_config() {
    if (compat_config_initialized_) {
        return;
    }
    if (!get_config_values_fn_ || !set_config_values_fn_) {
        compat_config_initialized_ = true;
        return;
    }

    auto get_cfg = reinterpret_cast<Oodle_GetConfigValuesFn>(get_config_values_fn_);
    auto set_cfg = reinterpret_cast<Oodle_SetConfigValuesFn>(set_config_values_fn_);

    std::array<std::uint8_t, 28> cfg{};
    std::memset(cfg.data(), 0, cfg.size());
    get_cfg(cfg.data());

    // Offset 20: m_OodleLZ_BackwardsCompatible_MajorVersion
    std::int32_t major = 9;
    std::memcpy(cfg.data() + 20, &major, sizeof(major));
    set_cfg(cfg.data());

    compat_config_initialized_ = true;
}

void OodleApi::decompress(
    std::span<const std::uint8_t> compressed,
    std::span<std::uint8_t> decompressed
) {
    if (compressed.empty()) {
        throw std::runtime_error(std::string("Oodle decompress: compressed buffer is empty"));
    }
    if (decompressed.empty()) {
        throw std::runtime_error(std::string("Oodle decompress: destination buffer is empty"));
    }

    auto fn = reinterpret_cast<OodleLZ_DecompressFn>(decompress_fn_);
    const long res =
        fn(compressed.data(), static_cast<long>(compressed.size()), decompressed.data(),
           static_cast<long>(decompressed.size()), 1, 1, 0, nullptr, 0, nullptr, nullptr, nullptr,
           0, 3);
    if (res == 0) {
        throw std::runtime_error(std::string("OodleLZ_Decompress returned 0"));
    }
}

std::vector<std::uint8_t> OodleApi::compress(
    std::span<const std::uint8_t> raw,
    OodleLZ_Compressor compressor,
    OodleLZ_CompressionLevel level
) {
    if (raw.empty()) {
        throw std::runtime_error(std::string("Oodle compress: raw buffer is empty"));
    }

    ensure_compat_config();

    auto get_size =
        reinterpret_cast<OodleLZ_GetCompressedBufferSizeNeededFn>(get_comp_buf_size_fn_);
    const int comp_id = static_cast<int>(compressor);
    const long raw_len = static_cast<long>(raw.size());
    const long max_out = get_size(comp_id, raw_len);
    if (max_out <= 0 || max_out > static_cast<long>(std::numeric_limits<int>::max())) {
        throw std::runtime_error(
            std::string("OodleLZ_GetCompressedBufferSizeNeeded returned invalid size")
        );
    }

    void* options = nullptr;
    if (get_default_options_fn_) {
        auto get_default =
            reinterpret_cast<OodleLZ_CompressOptions_GetDefaultFn>(get_default_options_fn_);
        options = get_default(comp_id, static_cast<int>(level));
    }

    std::vector<std::uint8_t> out(static_cast<std::size_t>(max_out));
    auto fn = reinterpret_cast<OodleLZ_CompressFn>(compress_fn_);
    const void* dictionary_base = nullptr;

    const long comp_len =
        fn(comp_id, raw.data(), raw_len, out.data(), static_cast<int>(level), options,
           dictionary_base, nullptr, nullptr, 0);
    if (comp_len <= 0 || comp_len > static_cast<long>(out.size())) {
        throw std::runtime_error(std::string("OodleLZ_Compress returned invalid length"));
    }
    out.resize(static_cast<std::size_t>(comp_len));
    return out;
}

OodleLZ_Compressor OodleApi::get_all_chunks_compressor(
    std::span<const std::uint8_t> compressed_chunk,
    std::size_t raw_len
) {
    if (compressed_chunk.empty() || raw_len == 0) {
        return OodleLZ_Compressor::Invalid;
    }
    auto fn = reinterpret_cast<OodleLZ_GetAllChunksCompressorFn>(get_all_chunks_compressor_fn_);
    const int res =
        fn(compressed_chunk.data(), static_cast<long>(compressed_chunk.size()),
           static_cast<long>(raw_len));
    return static_cast<OodleLZ_Compressor>(res);
}
}  // namespace bl4::ncs
