/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#include "ncs/ncs_file.h"
#include "ncs/ncs_crc32.h"

#include <blake3.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>

namespace bl4::ncs {
std::uint32_t read_u32_le(std::span<const std::uint8_t> s, std::size_t off) {
    return static_cast<std::uint32_t>(s[off]) | (static_cast<std::uint32_t>(s[off + 1]) << 8)
           | (static_cast<std::uint32_t>(s[off + 2]) << 16)
           | (static_cast<std::uint32_t>(s[off + 3]) << 24);
}

std::uint32_t read_u32_be(std::span<const std::uint8_t> s, std::size_t off) {
    return (static_cast<std::uint32_t>(s[off]) << 24)
           | (static_cast<std::uint32_t>(s[off + 1]) << 16)
           | (static_cast<std::uint32_t>(s[off + 2]) << 8) | static_cast<std::uint32_t>(s[off + 3]);
}

std::uint64_t read_u64_be(std::span<const std::uint8_t> s, std::size_t off) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | static_cast<std::uint64_t>(s[off + static_cast<std::size_t>(i)]);
    }
    return v;
}

void write_u32_le(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFu));
}

void write_u32_be(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
}

void write_u64_be(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu));
    }
}

std::array<std::uint8_t, 32> blake3_hash32(std::span<const std::uint8_t> payload) {
    std::array<std::uint8_t, 32> out{};
    blake3_hasher h{};
    blake3_hasher_init(&h);
    if (!payload.empty()) {
        blake3_hasher_update(&h, payload.data(), payload.size());
    }
    blake3_hasher_finalize(&h, out.data(), out.size());
    return out;
}

NcsFile parse_ncs(std::span<const std::uint8_t> file_bytes, OodleApi* oodle) {
    if (file_bytes.size() < 16) {
        throw std::runtime_error(std::string("NCS blob too small for header"));
    }

    NcsHeader hdr{};
    hdr.magic = read_u32_le(file_bytes, 0);
    hdr.flags = read_u32_le(file_bytes, 4);
    hdr.uncompressed_size = read_u32_le(file_bytes, 8);
    hdr.body_size = read_u32_le(file_bytes, 12);

    const std::uint32_t sig = hdr.magic & 0xFFFFFF00u;
    if (sig != 0x53434E00u) {
        throw std::runtime_error(std::string("Not an NCS file (bad magic)"));
    }
    if (file_bytes.size() - 16 != hdr.body_size) {
        throw std::runtime_error(std::string("NCS bodySize mismatch"));
    }

    if (hdr.flags == 0) {
        std::vector<std::uint8_t> payload(hdr.body_size);
        if (!payload.empty()) {
            std::memcpy(payload.data(), file_bytes.data() + 16, payload.size());
        }
        return NcsFile{hdr, std::nullopt, {}, std::move(payload)};
    }

    const std::size_t body_offset = 16;
    if (hdr.body_size < 64) {
        throw std::runtime_error(std::string("NCS body too small for compressed header"));
    }

    const auto hdr64 = file_bytes.subspan(body_offset, 64);
    NcsBlockHeader bh{};
    bh.magic_be = read_u32_be(hdr64, 0);
    bh.header_crc_be = read_u32_be(hdr64, 4);
    bh.codec = hdr64[8];
    bh.oodle_compressor_sel = hdr64[9];
    bh.oodle_level = static_cast<std::int8_t>(hdr64[10]);
    bh.chunk_shift = hdr64[11];
    bh.chunk_count_be = read_u32_be(hdr64, 12);
    bh.uncompressed_total_be = read_u64_be(hdr64, 16);
    bh.compressed_total_be = read_u64_be(hdr64, 24);
    std::memcpy(bh.header_tail32.data(), hdr64.data() + 32, 32);

    if (bh.magic_be != 0xB7756362u) {
        throw std::runtime_error(std::string("Unexpected block header magic"));
    }

    const std::uint32_t chunk_count_u32 = bh.chunk_count_be;
    const int chunk_count = static_cast<int>(chunk_count_u32);
    if (chunk_count < 0) {
        throw std::runtime_error(std::string("Negative chunkCount"));
    }

    const int header_size = (bh.codec == 0) ? 64 : 64 + 4 * chunk_count;
    if (hdr.body_size < static_cast<std::uint32_t>(header_size)) {
        throw std::runtime_error(std::string("NCS body too small for header/chunk table"));
    }

    // CRC32 of header bytes starting at offset 8 (skip magic + crc itself).
    const auto header_buf = file_bytes.subspan(body_offset, static_cast<std::size_t>(header_size));
    const std::uint32_t crc_calc = crc32_iso(header_buf.data() + 8, header_buf.size() - 8);
    if (crc_calc != bh.header_crc_be) {
        throw std::runtime_error(std::string("Header CRC mismatch"));
    }

    if (bh.compressed_total_be != hdr.body_size) {
        throw std::runtime_error(std::string("CompressedTotal mismatch"));
    }
    if (bh.uncompressed_total_be != hdr.uncompressed_size) {
        throw std::runtime_error(std::string("UncompressedTotal mismatch"));
    }

    std::vector<std::uint32_t> chunk_sizes;
    if (bh.codec != 0) {
        chunk_sizes.resize(static_cast<std::size_t>(chunk_count));
        const std::size_t table_offset = body_offset + 64;
        for (int i = 0; i < chunk_count; i++) {
            const std::size_t off = table_offset + 4 * static_cast<std::size_t>(i);
            chunk_sizes[static_cast<std::size_t>(i)] = read_u32_be(file_bytes, off);
        }
    }

    if (bh.codec == 0) {
        const std::size_t data_offset = body_offset + 64;
        if (data_offset + hdr.uncompressed_size > file_bytes.size()) {
            throw std::runtime_error(std::string("NCS body too small for raw payload"));
        }
        std::vector<std::uint8_t> payload(hdr.uncompressed_size);
        if (!payload.empty()) {
            std::memcpy(payload.data(), file_bytes.data() + data_offset, payload.size());
        }
        return NcsFile{hdr, bh, {}, std::move(payload)};
    }

    // Intentionally only support Oodle (codec=3). If LZ4 (codec=4) or any other codec, fail fast so
    // it can be investigated and then implemented if ever used.
    if (bh.codec != 3) {
        throw std::runtime_error(
            std::string("Unsupported NCS codec: ") + std::to_string(static_cast<unsigned>(bh.codec))
        );
    }

    if (bh.chunk_shift >= 31) {
        throw std::runtime_error(std::string("Invalid chunkShift"));
    }

    const int chunk_size = 1 << bh.chunk_shift;
    std::vector<std::uint8_t> out_buf(hdr.uncompressed_size);
    std::size_t cur_in = body_offset + static_cast<std::size_t>(header_size);
    std::size_t cur_out = 0;

    for (int i = 0; i < chunk_count; i++) {
        const std::uint32_t stored_len_u32 = chunk_sizes[static_cast<std::size_t>(i)];
        const std::size_t stored_len = static_cast<std::size_t>(stored_len_u32);
        if (cur_in + stored_len > file_bytes.size()) {
            throw std::runtime_error(std::string("Chunk range out of bounds"));
        }

        const std::size_t remaining = out_buf.size() - cur_out;
        const std::size_t this_out_len = std::min(remaining, static_cast<std::size_t>(chunk_size));

        const auto chunk_data = file_bytes.subspan(cur_in, stored_len);
        auto chunk_out = std::span<std::uint8_t>(out_buf.data() + cur_out, this_out_len);

        if (stored_len >= this_out_len) {
            std::memcpy(chunk_out.data(), chunk_data.data(), this_out_len);
        } else {
            if (!oodle) {
                throw std::runtime_error(
                    std::string("NCS uses Oodle compression, but no Oodle API is available")
                );
            }
            oodle->decompress(chunk_data, chunk_out);
        }

        cur_in += stored_len;
        cur_out += this_out_len;
    }

    if (cur_out != out_buf.size()) {
        throw std::runtime_error(std::string("Decompression did not fill the output buffer"));
    }

    return NcsFile{hdr, bh, std::move(chunk_sizes), std::move(out_buf)};
}

static std::vector<std::uint8_t> build_uncompressed(
    std::uint8_t type_byte,
    std::uint32_t flags,
    std::span<const std::uint8_t> payload
) {
    const std::uint32_t body_size = static_cast<std::uint32_t>(payload.size());
    std::vector<std::uint8_t> out;
    out.reserve(16 + payload.size());
    write_u32_le(out, 0x53434E00u | type_byte);
    write_u32_le(out, flags);
    write_u32_le(out, body_size);
    write_u32_le(out, body_size);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<std::uint8_t> build_ncs_from_decomp(
    std::span<const std::uint8_t> payload,
    const NcsBuildOptions& opt,
    OodleApi* oodle
) {
    if (payload.empty()) {
        throw std::runtime_error(std::string("payload is empty"));
    }

    if (opt.flags == 0) {
        return build_uncompressed(opt.type_byte, opt.flags, payload);
    }

    if (opt.codec != 0 && opt.codec != 3) {
        throw std::runtime_error(
            std::string("Unsupported NCS codec: ")
            + std::to_string(static_cast<unsigned>(opt.codec))
        );
    }

    if (opt.chunk_shift >= 31) {
        throw std::runtime_error(std::string("invalid chunkShift"));
    }

    std::array<std::uint8_t, 32> tail32 =
        opt.header_tail32.has_value() ? *opt.header_tail32 : blake3_hash32(payload);

    if (opt.codec == 0) {
        const std::uint32_t uncompressed_size0 = static_cast<std::uint32_t>(payload.size());
        const std::uint32_t body_size0 = static_cast<std::uint32_t>(64 + payload.size());

        std::vector<std::uint8_t> header;
        header.reserve(64);
        write_u32_be(header, 0xB7756362u);
        write_u32_be(header, 0);  // crc placeholder
        header.push_back(opt.codec);
        header.push_back(opt.oodle_compressor_sel);
        header.push_back(static_cast<std::uint8_t>(opt.oodle_level));
        header.push_back(opt.chunk_shift);
        write_u32_be(header, 1u);
        write_u64_be(header, uncompressed_size0);
        write_u64_be(header, body_size0);
        header.insert(header.end(), tail32.begin(), tail32.end());
        if (header.size() != 64) {
            throw std::runtime_error(std::string("codec=0 header size mismatch"));
        }

        const std::uint32_t crc = crc32_iso(header.data() + 8, header.size() - 8);
        header[4] = static_cast<std::uint8_t>((crc >> 24) & 0xFFu);
        header[5] = static_cast<std::uint8_t>((crc >> 16) & 0xFFu);
        header[6] = static_cast<std::uint8_t>((crc >> 8) & 0xFFu);
        header[7] = static_cast<std::uint8_t>(crc & 0xFFu);

        std::vector<std::uint8_t> out;
        out.reserve(16 + header.size() + payload.size());
        write_u32_le(out, 0x53434E00u | opt.type_byte);
        write_u32_le(out, opt.flags);
        write_u32_le(out, uncompressed_size0);
        write_u32_le(out, body_size0);
        out.insert(out.end(), header.begin(), header.end());
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    const int chunk_size = 1 << opt.chunk_shift;
    const int chunk_count = static_cast<int>(
        (payload.size() + static_cast<std::size_t>(chunk_size) - 1)
        / static_cast<std::size_t>(chunk_size)
    );

    std::vector<std::vector<std::uint8_t>> stored_chunks;
    stored_chunks.reserve(static_cast<std::size_t>(chunk_count));
    std::vector<std::uint32_t> chunk_sizes(static_cast<std::size_t>(chunk_count), 0);

    std::size_t offset = 0;
    for (int i = 0; i < chunk_count; i++) {
        const std::size_t raw_len =
            std::min(payload.size() - offset, static_cast<std::size_t>(chunk_size));
        const auto raw_chunk = payload.subspan(offset, raw_len);

        std::vector<std::uint8_t> stored;
        if (opt.codec == 3) {
            if (!oodle) {
                throw std::runtime_error(std::string("codec=3 requires Oodle"));
            }
            stored = oodle->compress(raw_chunk, opt.compressor, opt.level);
            if (stored.size() >= raw_len) {
                stored.assign(raw_chunk.begin(), raw_chunk.end());
            }
        } else {
            stored.assign(raw_chunk.begin(), raw_chunk.end());
        }

        chunk_sizes[static_cast<std::size_t>(i)] = static_cast<std::uint32_t>(stored.size());
        stored_chunks.push_back(std::move(stored));
        offset += raw_len;
    }

    const int header_size = 64 + 4 * chunk_count;
    std::size_t chunk_data_total = 0;
    for (const auto& c : stored_chunks) {
        chunk_data_total += c.size();
    }

    const std::uint32_t body_size = static_cast<std::uint32_t>(header_size + chunk_data_total);
    const std::uint32_t uncompressed_size = static_cast<std::uint32_t>(payload.size());

    std::vector<std::uint8_t> header;
    header.reserve(static_cast<std::size_t>(header_size));
    write_u32_be(header, 0xB7756362u);
    write_u32_be(header, 0);  // crc placeholder
    header.push_back(opt.codec);
    header.push_back(opt.oodle_compressor_sel);
    header.push_back(static_cast<std::uint8_t>(opt.oodle_level));
    header.push_back(opt.chunk_shift);
    write_u32_be(header, static_cast<std::uint32_t>(chunk_count));
    write_u64_be(header, uncompressed_size);
    write_u64_be(header, body_size);
    header.insert(header.end(), tail32.begin(), tail32.end());
    for (int i = 0; i < chunk_count; i++) {
        write_u32_be(header, chunk_sizes[static_cast<std::size_t>(i)]);
    }
    if (static_cast<int>(header.size()) != header_size) {
        throw std::runtime_error(std::string("header size mismatch"));
    }

    const std::uint32_t crc = crc32_iso(header.data() + 8, header.size() - 8);
    header[4] = static_cast<std::uint8_t>((crc >> 24) & 0xFFu);
    header[5] = static_cast<std::uint8_t>((crc >> 16) & 0xFFu);
    header[6] = static_cast<std::uint8_t>((crc >> 8) & 0xFFu);
    header[7] = static_cast<std::uint8_t>(crc & 0xFFu);

    std::vector<std::uint8_t> out;
    out.reserve(16 + static_cast<std::size_t>(body_size));
    write_u32_le(out, 0x53434E00u | opt.type_byte);
    write_u32_le(out, opt.flags);
    write_u32_le(out, uncompressed_size);
    write_u32_le(out, body_size);
    out.insert(out.end(), header.begin(), header.end());
    for (const auto& c : stored_chunks) {
        out.insert(out.end(), c.begin(), c.end());
    }

    return out;
}
}  // namespace bl4::ncs
