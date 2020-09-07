#pragma once

#include <cstdint>
#include <x86intrin.h>
#include <span>

template <size_t bits>
class AesKeySchedule;
template <size_t bits>
__m128i AesEncrypt(const AesKeySchedule<bits>& key, __m128i block);
template <size_t bits>
class AesKeySchedule {
public:
  explicit AesKeySchedule(const std::span<uint8_t>& key);
private:
  static constexpr size_t rounds = 6 + bits / 32;
  __m128i eroundKeys[rounds + 1];
  template <size_t N>
  friend __m128i AesEncrypt(const AesKeySchedule<N>& key, __m128i block);
};

template <size_t bits>
__m128i AesEncrypt(const AesKeySchedule<bits>& key, __m128i block) {
  block ^= key.eroundKeys[0];
  for (size_t n = 1; n < key.rounds; n++) {
    block = _mm_aesenc_si128(block, key.eroundKeys[n]);
  }
  block = _mm_aesenclast_si128(block, key.eroundKeys[key.rounds]);
  return block;
}

template <size_t bits>
struct AES {
  static constexpr size_t size = 16;
  static constexpr size_t ivsize = 12;
  static constexpr size_t keysize = bits / 8;
  using KeySchedule = AesKeySchedule<bits>;
  static inline __m128i Encrypt(const KeySchedule& key, __m128i block) {
    return AesEncrypt(key, block);
  }
};


