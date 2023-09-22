#pragma once

#include <x86intrin.h>
#include <span>
#include <cstring>
#include "caligo/key_iv_pair.h"

namespace Caligo {

template <typename Cipher>
struct CTR {
  CTR(key_iv_pair<Cipher> key_iv) 
  : sched(key_iv.key)
  , iv(key_iv.iv)
  {
    if (key_iv.key.size() != Cipher::keysize ||
        key_iv.iv.size() != Cipher::size) {
      throw std::runtime_error("Invalid IV");
    }
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
  std::vector<uint8_t> GenerateKeystream(size_t size) {
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
    if (iv.size() == 12) {
      ctr[12] = ctr[13] = ctr[14] = 0;
      ctr[15] = 1;
    }
    message_counter++;

    std::vector<uint8_t> keystream;
    size_t blocks = (size + Cipher::size - 1) / Cipher::size;
    keystream.reserve(blocks * Cipher::size);
    for (size_t n = 0; n < blocks; n++) {
      ctr_inc(ctr);
      __m128i block = Cipher::Encrypt(sched, _mm_loadu_si128((__m128i*)ctr.data()));
      _mm_storeu_si128((__m128i*)(keystream.data() + n * Cipher::size), block);
    }
    keystream.resize(size);
    return keystream;
  }
  void Decrypt(std::span<uint8_t> ciphertext) {
    auto keystream = GenerateKeystream(ciphertext.size());
    for (size_t n = 0; n < ciphertext.size(); n++) {
      ciphertext[n] ^= keystream[n];
    }
  }
  void Encrypt(std::span<uint8_t> plaintext) {
    auto keystream = GenerateKeystream(plaintext.size());
    for (size_t n = 0; n < plaintext.size(); n++) {
      plaintext[n] ^= keystream[n];
    }
  }
  typename Cipher::KeySchedule sched;
  uint64_t message_counter = 0;
  std::vector<uint8_t> iv;
};

}

