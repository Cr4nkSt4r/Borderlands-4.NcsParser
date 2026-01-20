/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace bl4::ncs {
class BitWriter {
   public:
    explicit BitWriter(std::size_t initial_bytes = 256)
        : buf_(initial_bytes < 32 ? 32 : initial_bytes, 0), bit_pos_(0) {}

    int bit_position() const { return bit_pos_; }
    int byte_length() const { return (bit_pos_ + 7) / 8; }

    void align_to_byte() {
        const int mod = bit_pos_ & 7;
        if (mod != 0) {
            write_bits(0, 8 - mod);
        }
    }

    void write_bits(std::uint32_t value, int bit_count) {
        if (bit_count < 0 || bit_count > 32) {
            throw std::invalid_argument("bit_count out of range");
        }
        ensure_capacity(bit_count);
        for (int i = 0; i < bit_count; i++) {
            const int byte_pos = bit_pos_ >> 3;
            const int bit_in_byte = bit_pos_ & 7;
            const std::uint32_t bit = (value >> i) & 1u;
            if (bit != 0) {
                buf_[static_cast<std::size_t>(byte_pos)] |=
                    static_cast<std::uint8_t>(1u << bit_in_byte);
            }
            bit_pos_++;
        }
    }

    void write_bytes_aligned(std::span<const std::uint8_t> bytes) {
        if ((bit_pos_ & 7) != 0) {
            throw std::runtime_error("write_bytes_aligned requires byte alignment");
        }
        if (bytes.empty()) {
            return;
        }
        ensure_capacity(static_cast<int>(bytes.size() * 8));
        const int byte_pos = bit_pos_ >> 3;
        std::memcpy(buf_.data() + static_cast<std::size_t>(byte_pos), bytes.data(), bytes.size());
        bit_pos_ += static_cast<int>(bytes.size() * 8);
    }

    std::vector<std::uint8_t> to_bytes() const {
        const int len = byte_length();
        std::vector<std::uint8_t> out(static_cast<std::size_t>(len));
        if (!out.empty()) {
            std::memcpy(out.data(), buf_.data(), out.size());
        }
        return out;
    }

   private:
    void ensure_capacity(int more_bits) {
        const int need_bits = bit_pos_ + more_bits;
        const int need_bytes = (need_bits + 7) / 8;
        if (need_bytes <= static_cast<int>(buf_.size())) {
            return;
        }
        std::size_t new_len = buf_.size();
        while (static_cast<int>(new_len) < need_bytes) {
            new_len *= 2;
        }
        buf_.resize(new_len, 0);
    }

    std::vector<std::uint8_t> buf_;
    int bit_pos_ = 0;
};
}  // namespace bl4::ncs
