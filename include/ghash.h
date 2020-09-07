#pragma once

#include <x86intrin.h>

inline void debug(const char* name, __m128i v) {
  uint8_t a[16];
  _mm_storeu_si128((__m128i*)a, v);
  printf("%s: ", name);
  for (auto& c : a) {
    printf("%02x", c);
  }
  printf("\n");
}

inline __m128i reflect(__m128i v) {
  static const __m128i x0 = _mm_setr_epi32(0xF0F0F0F0, 0xF0F0F0F0, 0xF0F0F0F0, 0xF0F0F0F0), 
                       y0 = _mm_setr_epi32(0x0F0F0F0F, 0x0F0F0F0F, 0x0F0F0F0F, 0x0F0F0F0F);
  static const __m128i x1 = _mm_setr_epi32(0xCCCCCCCC, 0xCCCCCCCC, 0xCCCCCCCC, 0xCCCCCCCC), 
                       y1 = _mm_setr_epi32(0x33333333, 0x33333333, 0x33333333, 0x33333333);
  static const __m128i x2 = _mm_setr_epi32(0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA), 
                       y2 = _mm_setr_epi32(0x55555555, 0x55555555, 0x55555555, 0x55555555);
  v = ((v >> 4) & y0) | ((v << 4) & x0);
  v = ((v >> 2) & y1) | ((v << 2) & x1);
  v = ((v >> 1) & y2) | ((v << 1) & x2);
  return v;
}

inline __m128i galoisMultiply(__m128i a, __m128i b) {
  __m128i tmp3, tmp4, tmp6, tmp8;
  __m128i XMMMASK = _mm_setr_epi32(0xffffffff, 0x0, 0x0, 0x0);
  tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
  tmp6 = _mm_clmulepi64_si128(a, b, 0x11);
  tmp4 = _mm_clmulepi64_si128(_mm_shuffle_epi32(a,78) ^ a, _mm_shuffle_epi32(b,78) ^ b, 0x00) ^ tmp3 ^ tmp6;
  tmp3 ^= _mm_slli_si128(tmp4, 8);
  tmp6 ^= _mm_srli_si128(tmp4, 8);
  tmp8 = _mm_shuffle_epi32(_mm_srli_epi32(tmp6, 31) ^ _mm_srli_epi32(tmp6, 30) ^ _mm_srli_epi32(tmp6, 25), 0x93);
  tmp3 = _mm_xor_si128(tmp3, _mm_andnot_si128(XMMMASK, tmp8));
  tmp6 = _mm_xor_si128(tmp6, _mm_and_si128(XMMMASK, tmp8));

  return tmp3 ^ tmp6 ^ _mm_slli_epi32(tmp6, 1) ^ _mm_slli_epi32(tmp6, 2) ^ _mm_slli_epi32(tmp6, 7);
}

inline __m128i ghash_block(__m128i x, __m128i h, __m128i hash) {
  return galoisMultiply(hash ^ x, h);
}

