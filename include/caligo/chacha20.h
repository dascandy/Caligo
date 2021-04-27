#pragma once

#include <cstdint>
#include <span>

struct ChaCha20 {
  uint32_t state[16];
  uint8_t buffer[64];
  uint8_t offset = 0;
  ChaCha20(std::span<const uint8_t> key, std::span<const uint8_t> nonce) {
    if (key.size() != 32) throw std::runtime_error("Invalid key size");
    if (nonce.size() != 12) throw std::runtime_error("Invalid nonce size");
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    state[4] = key[0] | (key[1] << 8) | (key[2] << 16) | (key[3] << 24);
    state[5] = key[4] | (key[5] << 8) | (key[6] << 16) | (key[7] << 24);
    state[6] = key[8] | (key[9] << 8) | (key[10] << 16) | (key[11] << 24);
    state[7] = key[12] | (key[13] << 8) | (key[14] << 16) | (key[15] << 24);
    state[8] = key[16] | (key[17] << 8) | (key[18] << 16) | (key[19] << 24);
    state[9] = key[20] | (key[21] << 8) | (key[22] << 16) | (key[23] << 24);
    state[10] = key[24] | (key[25] << 8) | (key[26] << 16) | (key[27] << 24);
    state[11] = key[28] | (key[29] << 8) | (key[30] << 16) | (key[31] << 24);
    state[12] = 1;
    state[13] = nonce[0] | (nonce[1] << 8) | (nonce[2] << 16) | (nonce[3] << 24);
    state[14] = nonce[4] | (nonce[5] << 8) | (nonce[6] << 16) | (nonce[7] << 24);
    state[15] = nonce[8] | (nonce[9] << 8) | (nonce[10] << 16) | (nonce[11] << 24);

    GenerateBlock();
  }
  void GenerateBlock() {
    uint32_t s[16] = {
      state[0], state[1], state[2], state[3],
      state[4], state[5], state[6], state[7],
      state[8], state[9], state[10], state[11],
      state[12], state[13], state[14], state[15],
    };

    for (size_t n = 0; n < 10; n++) {
      s[0] += s[4]; s[12] ^= s[0]; s[12] = ((s[12] << 16) | (s[12] >> 16));
      s[8] += s[12]; s[4] ^= s[8]; s[4] = ((s[4] << 12) | (s[4] >> 20));
      s[0] += s[4]; s[12] ^= s[0]; s[12] = ((s[12] << 8) | (s[12] >> 24));
      s[8] += s[12]; s[4] ^= s[8]; s[4] = ((s[4] << 7) | (s[4] >> 25));

      s[1] += s[5]; s[13] ^= s[1]; s[13] = ((s[13] << 16) | (s[13] >> 16));
      s[9] += s[13]; s[5] ^= s[9]; s[5] = ((s[5] << 12) | (s[5] >> 20));
      s[1] += s[5]; s[13] ^= s[1]; s[13] = ((s[13] << 8) | (s[13] >> 24));
      s[9] += s[13]; s[5] ^= s[9]; s[5] = ((s[5] << 7) | (s[5] >> 25));

      s[2] += s[6]; s[14] ^= s[2]; s[14] = ((s[14] << 16) | (s[14] >> 16));
      s[10] += s[14]; s[6] ^= s[10]; s[6] = ((s[6] << 12) | (s[6] >> 20));
      s[2] += s[6]; s[14] ^= s[2]; s[14] = ((s[14] << 8) | (s[14] >> 24));
      s[10] += s[14]; s[6] ^= s[10]; s[6] = ((s[6] << 7) | (s[6] >> 25));

      s[3] += s[7]; s[15] ^= s[3]; s[15] = ((s[15] << 16) | (s[15] >> 16));
      s[11] += s[15]; s[7] ^= s[11]; s[7] = ((s[7] << 12) | (s[7] >> 20));
      s[3] += s[7]; s[15] ^= s[3]; s[15] = ((s[15] << 8) | (s[15] >> 24));
      s[11] += s[15]; s[7] ^= s[11]; s[7] = ((s[7] << 7) | (s[7] >> 25));

      s[0] += s[5]; s[15] ^= s[0]; s[15] = ((s[15] << 16) | (s[15] >> 16));
      s[10] += s[15]; s[5] ^= s[10]; s[5] = ((s[5] << 12) | (s[5] >> 20));
      s[0] += s[5]; s[15] ^= s[0]; s[15] = ((s[15] << 8) | (s[15] >> 24));
      s[10] += s[15]; s[5] ^= s[10]; s[5] = ((s[5] << 7) | (s[5] >> 25));

      s[1] += s[6]; s[12] ^= s[1]; s[12] = ((s[12] << 16) | (s[12] >> 16));
      s[11] += s[12]; s[6] ^= s[11]; s[6] = ((s[6] << 12) | (s[6] >> 20));
      s[1] += s[6]; s[12] ^= s[1]; s[12] = ((s[12] << 8) | (s[12] >> 24));
      s[11] += s[12]; s[6] ^= s[11]; s[6] = ((s[6] << 7) | (s[6] >> 25));

      s[2] += s[7]; s[13] ^= s[2]; s[13] = ((s[13] << 16) | (s[13] >> 16));
      s[8] += s[13]; s[7] ^= s[8]; s[7] = ((s[7] << 12) | (s[7] >> 20));
      s[2] += s[7]; s[13] ^= s[2]; s[13] = ((s[13] << 8) | (s[13] >> 24));
      s[8] += s[13]; s[7] ^= s[8]; s[7] = ((s[7] << 7) | (s[7] >> 25));

      s[3] += s[4]; s[14] ^= s[3]; s[14] = ((s[14] << 16) | (s[14] >> 16));
      s[9] += s[14]; s[4] ^= s[9]; s[4] = ((s[4] << 12) | (s[4] >> 20));
      s[3] += s[4]; s[14] ^= s[3]; s[14] = ((s[14] << 8) | (s[14] >> 24));
      s[9] += s[14]; s[4] ^= s[9]; s[4] = ((s[4] << 7) | (s[4] >> 25));
    }

    for (size_t n = 0; n < 16; n++) {
      s[n] += state[n];
      for (size_t c = 0; c < 32; c += 8) {
        buffer[n*4+c/8] = (s[n] >> c);
      }
    }
    state[12]++;
    offset = 0;
  };
  void Encrypt(std::span<uint8_t> data) {
    for (auto& c : data) {
      c ^= buffer[offset++];
      if (offset == 64) {
        GenerateBlock();
      }
    }
  }
  void Decrypt(std::span<uint8_t> data) {
    for (auto& c : data) {
      c ^= buffer[offset++];
      if (offset == 64) {
        GenerateBlock();
      }
    }
  }
};


