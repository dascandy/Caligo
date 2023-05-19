#pragma once

#include <x86intrin.h>
#include <span>
#include <cstring>
#include "caligo/key_iv_pair.h"

namespace Caligo {

template <typename Cipher>
struct ECB {
  ECB(std::array<uint8_t, Cipher::size> key)
  : sched(key)
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
      Cipher::Encrypt(sched, plaintext.data() + n);
    }
  }
  typename Cipher::KeySchedule sched;
};

}

