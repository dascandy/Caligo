#include "caligo/aes.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#ifdef __x86_64__
#include <x86intrin.h>

namespace Caligo {

template <uint8_t round>
static __m128i nextRoundKey(__m128i in) {
  constexpr const uint8_t roundConstants[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
  auto t = in ^ _mm_srli_si128(_mm_aeskeygenassist_si128(in, roundConstants[round]), 0x0c);
  return t ^ _mm_slli_si128 (t, 0x4) ^ _mm_slli_si128 (t, 0x8) ^ _mm_slli_si128 (t, 0xC);
}

template <>
AesKeySchedule<128>::AesKeySchedule(std::span<const uint8_t> key) {
  std::memcpy(eroundKeys, key.data(), key.size());

  eroundKeys[1] = nextRoundKey<0>(eroundKeys[0]);
  eroundKeys[2] = nextRoundKey<1>(eroundKeys[1]);
  eroundKeys[3] = nextRoundKey<2>(eroundKeys[2]);
  eroundKeys[4] = nextRoundKey<3>(eroundKeys[3]);
  eroundKeys[5] = nextRoundKey<4>(eroundKeys[4]);
  eroundKeys[6] = nextRoundKey<5>(eroundKeys[5]);
  eroundKeys[7] = nextRoundKey<6>(eroundKeys[6]);
  eroundKeys[8] = nextRoundKey<7>(eroundKeys[7]);
  eroundKeys[9] = nextRoundKey<8>(eroundKeys[8]);
  eroundKeys[10] = nextRoundKey<9>(eroundKeys[9]);
}

template <>
AesKeySchedule<256>::AesKeySchedule(std::span<const uint8_t> key) {
  __m128i a = _mm_loadu_si128((__m128i*)key.data()), b = _mm_loadu_si128((__m128i*)(key.data()+16));
  eroundKeys[0]=a;
  eroundKeys[1]=b;
  a ^= _mm_slli_si128 (a, 0x4) ^ _mm_slli_si128 (a, 0x8) ^ _mm_slli_si128 (a, 0xC) ^ _mm_shuffle_epi32(_mm_aeskeygenassist_si128 (b,0x01), 0xff);
  b ^= _mm_slli_si128(b, 0x4) ^ _mm_slli_si128(b, 0x8) ^ _mm_slli_si128(b, 0x0C) ^ _mm_shuffle_epi32(_mm_aeskeygenassist_si128 (a, 0x0), 0xaa);
  eroundKeys[2]=a;
  eroundKeys[3]=b;
  a ^= _mm_slli_si128 (a, 0x4) ^ _mm_slli_si128 (a, 0x8) ^ _mm_slli_si128 (a, 0xC) ^ _mm_shuffle_epi32(_mm_aeskeygenassist_si128 (b,0x02), 0xff);
  b ^= _mm_slli_si128(b, 0x4) ^ _mm_slli_si128(b, 0x8) ^ _mm_slli_si128(b, 0x0C) ^ _mm_shuffle_epi32(_mm_aeskeygenassist_si128 (a, 0x0), 0xaa);
  eroundKeys[4]=a;
  eroundKeys[5]=b;
  a ^= _mm_slli_si128 (a, 0x4) ^ _mm_slli_si128 (a, 0x8) ^ _mm_slli_si128 (a, 0xC) ^ _mm_shuffle_epi32(_mm_aeskeygenassist_si128 (b,0x04), 0xff);
  b ^= _mm_slli_si128(b, 0x4) ^ _mm_slli_si128(b, 0x8) ^ _mm_slli_si128(b, 0x0C) ^ _mm_shuffle_epi32(_mm_aeskeygenassist_si128 (a, 0x0), 0xaa);
  eroundKeys[6]=a;
  eroundKeys[7]=b;
  a ^= _mm_slli_si128 (a, 0x4) ^ _mm_slli_si128 (a, 0x8) ^ _mm_slli_si128 (a, 0xC) ^ _mm_shuffle_epi32(_mm_aeskeygenassist_si128 (b,0x08), 0xff);
  b ^= _mm_slli_si128(b, 0x4) ^ _mm_slli_si128(b, 0x8) ^ _mm_slli_si128(b, 0x0C) ^ _mm_shuffle_epi32(_mm_aeskeygenassist_si128 (a, 0x0), 0xaa);
  eroundKeys[8]=a;
  eroundKeys[9]=b;
  a ^= _mm_slli_si128 (a, 0x4) ^ _mm_slli_si128 (a, 0x8) ^ _mm_slli_si128 (a, 0xC) ^ _mm_shuffle_epi32(_mm_aeskeygenassist_si128 (b,0x10), 0xff);
  b ^= _mm_slli_si128(b, 0x4) ^ _mm_slli_si128(b, 0x8) ^ _mm_slli_si128(b, 0x0C) ^ _mm_shuffle_epi32(_mm_aeskeygenassist_si128 (a, 0x0), 0xaa);
  eroundKeys[10]=a;
  eroundKeys[11]=b;
  a ^= _mm_slli_si128 (a, 0x4) ^ _mm_slli_si128 (a, 0x8) ^ _mm_slli_si128 (a, 0xC) ^ _mm_shuffle_epi32(_mm_aeskeygenassist_si128 (b,0x20), 0xff);
  b ^= _mm_slli_si128(b, 0x4) ^ _mm_slli_si128(b, 0x8) ^ _mm_slli_si128(b, 0x0C) ^ _mm_shuffle_epi32(_mm_aeskeygenassist_si128 (a, 0x0), 0xaa);
  eroundKeys[12]=a;
  eroundKeys[13]=b;
  a ^= _mm_slli_si128 (a, 0x4) ^ _mm_slli_si128 (a, 0x8) ^ _mm_slli_si128 (a, 0xC) ^ _mm_shuffle_epi32(_mm_aeskeygenassist_si128 (b,0x40), 0xff);
  eroundKeys[14]=a;
}

}
#else
#error Not implemented
#endif
