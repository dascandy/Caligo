#pragma once

#include "caligo/ghash.h"
#include <x86intrin.h>
#include <span>
#include <cstring>
#include "caligo/key_iv_pair.h"

namespace Caligo {

template <typename Cipher>
struct GCM {
  GCM(key_iv_pair<Cipher> key_iv) 
  : sched(key_iv.key)
  , iv(key_iv.iv)
  {
    if (iv.size() != Cipher::size - 4) {
      auto reduced_iv = ghash({}, iv);
      iv.resize(16);
      copy_n(reduced_iv.begin(), 16, iv.begin());
    }

    h = reflect(Cipher::Encrypt(sched, {0,0}));
  }
  void ctr_inc(std::array<uint8_t, Cipher::size>& ctr) {
    ctr[15]++;
    if (ctr[15] != 0) return;
    ctr[14]++;
    if (ctr[14] != 0) return;
    ctr[13]++;
    if (ctr[13] != 0) return;
    ctr[12]++;
  }
  std::array<uint8_t, 16> ghash(const std::span<const uint8_t> ciphertext, const std::span<const uint8_t> aad) {
    size_t aad_blocks = aad.size() / Cipher::size;
    size_t text_blocks = ciphertext.size() / Cipher::size;
    __m128i chash = { 0, 0};
    for (size_t n = 0; n < aad_blocks; n++) {
      chash = ghash_block(reflect(_mm_loadu_si128((__m128i*)(aad.data() + Cipher::size*n))), h, chash);
    }
    if (size_t bytes = aad.size() - aad_blocks * Cipher::size; bytes > 0) {
      std::array<uint8_t, Cipher::size> buffer;
      memcpy(buffer.data(), aad.data() + aad.size() - bytes, bytes);
      memset(buffer.data() + bytes, 0, Cipher::size - bytes);
      chash = ghash_block(reflect(_mm_loadu_si128((__m128i*)(buffer.data()))), h, chash);
    }
    for (size_t n = 0; n < text_blocks; n++) {
      chash = ghash_block(reflect(_mm_loadu_si128((__m128i*)(ciphertext.data() + Cipher::size*n))), h, chash);
    }
    if (size_t bytes = ciphertext.size() - text_blocks * Cipher::size; bytes > 0) {
      std::array<uint8_t, Cipher::size> buffer;
      memcpy(buffer.data(), ciphertext.data() + ciphertext.size() - bytes, bytes);
      memset(buffer.data() + bytes, 0, Cipher::size - bytes);
      chash = ghash_block(reflect(_mm_loadu_si128((__m128i*)(buffer.data()))), h, chash);
    }

    size_t ptsize = ciphertext.size() * 8, aadsize = aad.size() * 8;
    uint8_t sizes[16];
    for (size_t n = 8; n --> 0;) {
      sizes[n] = aadsize & 0xFF;
      sizes[n + 8] = ptsize & 0xFF;
      aadsize >>= 8;
      ptsize >>= 8;
    }
    chash = ghash_block(reflect(_mm_loadu_si128((__m128i*)(sizes))), h, chash);

    std::array<uint8_t, 16> calc_tag;
    _mm_storeu_si128((__m128i*)calc_tag.data(), reflect(chash));
    return calc_tag;
  }
  std::array<uint8_t, 16> calculate_tag(const std::span<const uint8_t> ciphertext, const std::span<const uint8_t> aad) {
    std::array<uint8_t, 16> tag = ghash(ciphertext, aad);
    
    __m128i chash = reflect(_mm_loadu_si128((__m128i*)tag.data()));
    chash ^= z;
    std::array<uint8_t, 16> calc_tag;
    _mm_storeu_si128((__m128i*)calc_tag.data(), reflect(chash));
    return calc_tag;
  }
  std::pair<std::vector<uint8_t>, bool> Decrypt(const std::span<const uint8_t> ciphertext, const std::span<const uint8_t> aad, std::array<uint8_t, 16> tag) {
    std::array<uint8_t, Cipher::size> ctr = {};
    memcpy(ctr.data(), iv.data(), iv.size());
    ctr[4] ^= ((message_counter >> 56) & 0xFF);
    ctr[5] ^= ((message_counter >> 48) & 0xFF);
    ctr[6] ^= ((message_counter >> 40) & 0xFF);
    ctr[7] ^= ((message_counter >> 32) & 0xFF);
    ctr[8] ^= ((message_counter >> 24) & 0xFF);
    ctr[9] ^= ((message_counter >> 16) & 0xFF);
    ctr[10] ^= ((message_counter >> 8) & 0xFF);
    ctr[11] ^= ((message_counter >> 0) & 0xFF);
    ctr_inc(ctr);
    z = reflect(Cipher::Encrypt(sched, _mm_loadu_si128((__m128i*)ctr.data())));
    message_counter++;

    std::vector<uint8_t> plaintext;
    size_t blocks = (ciphertext.size() + Cipher::size - 1) / Cipher::size;
    plaintext.resize(blocks * Cipher::size);
    for (size_t n = 0; n < blocks; n++) {
      ctr_inc(ctr);
      __m128i block = Cipher::Encrypt(sched, _mm_loadu_si128((__m128i*)ctr.data()));
      _mm_storeu_si128((__m128i*)(plaintext.data() + n * Cipher::size), block);
      for (size_t k = 0; k < std::min(ciphertext.size() - n * Cipher::size, Cipher::size); k++) {
        plaintext[n * Cipher::size + k] ^= ciphertext[n * Cipher::size + k];
      }
    }
    plaintext.resize(ciphertext.size());
    std::array<uint8_t, 16> calc_tag = calculate_tag(ciphertext, aad);
    return {std::move(plaintext), iv.size() >= 8 && calc_tag == tag};
  }
  std::pair<std::vector<uint8_t>, std::array<uint8_t, 16>> Encrypt(const std::span<const uint8_t> plaintext, const std::span<const uint8_t> aad) {
    std::array<uint8_t, Cipher::size> ctr = {};
    memcpy(ctr.data(), iv.data(), iv.size());
    ctr[4] ^= ((message_counter >> 56) & 0xFF);
    ctr[5] ^= ((message_counter >> 48) & 0xFF);
    ctr[6] ^= ((message_counter >> 40) & 0xFF);
    ctr[7] ^= ((message_counter >> 32) & 0xFF);
    ctr[8] ^= ((message_counter >> 24) & 0xFF);
    ctr[9] ^= ((message_counter >> 16) & 0xFF);
    ctr[10] ^= ((message_counter >> 8) & 0xFF);
    ctr[11] ^= ((message_counter >> 0) & 0xFF);
    ctr_inc(ctr);
    z = reflect(Cipher::Encrypt(sched, _mm_loadu_si128((__m128i*)ctr.data())));
    message_counter++;

    std::vector<uint8_t> ciphertext;
    size_t blocks = (plaintext.size() + Cipher::size - 1) / Cipher::size;
    ciphertext.resize(blocks * Cipher::size);
    for (size_t n = 0; n < blocks; n++) {
      ctr_inc(ctr);
      __m128i block = Cipher::Encrypt(sched, _mm_loadu_si128((__m128i*)ctr.data()));
      _mm_storeu_si128((__m128i*)(ciphertext.data() + n * Cipher::size), block);
      for (size_t k = 0; k < std::min(plaintext.size() - n * Cipher::size, Cipher::size); k++) {
        ciphertext[n * Cipher::size + k] ^= plaintext[n * Cipher::size + k];
      }
    }
    ciphertext.resize(plaintext.size());

    std::array<uint8_t, 16> calc_tag = calculate_tag(ciphertext, aad);
    return {std::move(ciphertext), std::move(calc_tag)};
  }
  typename Cipher::KeySchedule sched;
  __m128i h, z;
  uint64_t message_counter = 0;
  std::vector<uint8_t> iv;
};

}

