/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#pragma once

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

namespace bl4::ncs {
class BitReader {
   public:
    explicit BitReader(std::span<const std::uint8_t> data)
        : _data(data), _bit_pos(0), _bit_len(static_cast<int>(data.size() * 8)) {}

    int bit_position() const { return _bit_pos; }
    int bit_length() const { return _bit_len; }

    bool read_bit() { return read_bits(1) != 0; }

    std::uint32_t read_bits(int bit_count) {
        if (bit_count < 0 || bit_count > 32) {
            throw std::invalid_argument(std::string("bitCount must be in [0..32]"));
        }
        if (bit_count == 0) {
            return 0;
        }

        std::uint32_t value = 0;
        for (int i = 0; i < bit_count; i++) {
            if (_bit_pos >= _bit_len) {
                throw std::runtime_error(std::string("Unexpected EOF while reading bits."));
            }
            const int byte_pos = _bit_pos >> 3;
            const int bit_in_byte = _bit_pos & 7;
            const std::uint32_t bit =
                (static_cast<std::uint32_t>(
                     _data[static_cast<std::size_t>(byte_pos)] >> bit_in_byte
                 )
                 & 1u);
            value |= bit << i;
            _bit_pos++;
        }
        return value;
    }

    void skip_bits(long long bit_count) {
        if (bit_count < 0) {
            throw std::invalid_argument(std::string("bitCount must be >= 0"));
        }
        const long long new_pos = static_cast<long long>(_bit_pos) + bit_count;
        if (new_pos > _bit_len) {
            throw std::runtime_error(std::string("Unexpected EOF while skipping bits."));
        }
        _bit_pos = static_cast<int>(new_pos);
    }

    void align_to_byte() {
        const int mod = _bit_pos & 7;
        if (mod != 0) {
            skip_bits(8 - mod);
        }
    }

    void seek(int bit_pos) {
        if (bit_pos < 0 || bit_pos > _bit_len) {
            throw std::invalid_argument(std::string("bitPos out of range"));
        }
        _bit_pos = bit_pos;
    }

   private:
    std::span<const std::uint8_t> _data;
    int _bit_pos;
    int _bit_len;
};
}  // namespace bl4::ncs
