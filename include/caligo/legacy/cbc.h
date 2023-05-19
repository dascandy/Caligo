#pragma once

#include <x86intrin.h>
#include <span>
#include <cstring>
#include "caligo/key_iv_pair.h"

namespace Caligo {

template <typename Cipher>
struct CBC {
  CBC(key_iv_pair<Cipher> key_iv)
  : sched(key_iv.key)
  , iv(key_iv.iv)
  {
  }
  void Decrypt(std::span<uint8_t> ciphertext) {
    assert((ciphertext.size() % Cipher::size) == 0);
    for (size_t n = 0; n < ciphertext.size(); n += Cipher::size) {
      Cipher::Decrypt(sched, ciphertext.data() + n);
    }
  }
  void Encrypt(std::span<uint8_t> plaintext) {
    assert((plaintext.size() % Cipher::size) == 0);
    for (size_t n = 0; n < plaintext.size(); n += Cipher::size) {
      if (n == 0) {
        xorOnto(plaintext.data(), iv.data(), Cipher::size);
      } else {
        xorOnto(plaintext.data() + n, plaintext.data() + n - Cipher::size, Cipher::size);
      }
      Cipher::Encrypt(sched, plaintext.data() + n);
    }
  }
  typename Cipher::KeySchedule sched;
  std::array<uint8_t, Cipher::size> iv;
};

}

