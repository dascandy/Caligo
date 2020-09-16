#include "caligo/sha2.h"
#include <cstdio>

SHA256::SHA256() {
  w[0] = 0x6a09e667;
  w[1] = 0xbb67ae85;
  w[2] = 0x3c6ef372;
  w[3] = 0xa54ff53a;
  w[4] = 0x510e527f;
  w[5] = 0x9b05688c;
  w[6] = 0x1f83d9ab;
  w[7] = 0x5be0cd19;
}

void SHA256::add(std::span<const uint8_t> data) {
  size_t offset = msglength % (2*hashsize);
  size_t inoffset = 0;
  msglength += data.size();
  if (offset) {
    size_t copyNow = std::min(data.size(), 2*hashsize - offset);
    memcpy(chunk+offset, data.data(), copyNow);
    inoffset = copyNow;
    offset += copyNow;
    if (offset != 2*hashsize) {
      return;
    }
    processChunk();
    offset = 0;
  }
  while (data.size() - inoffset >= (2*hashsize)) {
    memcpy(chunk, data.data() + inoffset, 2*hashsize);
    processChunk();
    inoffset += 2*hashsize;
  }
  if (data.size() - inoffset)
    memcpy(chunk, data.data() + inoffset, data.size() - inoffset);
}

static uint32_t rotr32(uint32_t v, size_t count) {
  return (v >> count) | (v << (32 - count));
}

static const uint32_t K_256[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void SHA256::processChunk() {
  uint32_t W[64];
  for (size_t t = 0; t < 16; t++) {
    W[t] = ((uint32_t)chunk[t*4] << 24) + (chunk[t*4+1] << 16) + (chunk[t*4+2] << 8) + (chunk[t*4+3]);
  }
  for (size_t t = 16; t < 64; t++) {
    W[t] = (rotr32(W[t-2], 17) ^ rotr32(W[t-2], 19) ^ (W[t-2] >> 10)) + (rotr32(W[t-15], 7) ^ rotr32(W[t-15], 18) ^ (W[t-15] >> 3)) + W[t-7] + W[t-16];
  }

  uint32_t a = w[0], b = w[1], c = w[2], d = w[3], e = w[4], f = w[5], g = w[6], h = w[7];
  for (size_t t = 0; t < 64; t++) {
    uint32_t T1 = h + (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) + ((e & f) | (~e & g)) + K_256[t] + W[t];
    uint32_t T2 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) + ((a&b) ^ (a&c) ^ (b&c));
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }
  w[0] += a;
  w[1] += b;
  w[2] += c;
  w[3] += d;
  w[4] += e;
  w[5] += f;
  w[6] += g;
  w[7] += h;
}

SHA256::operator std::vector<uint8_t>() const {
  auto copy = *this;
  uint64_t padsize = 2*hashsize - ((msglength + 8) % (2*hashsize));
  uint8_t zeroes[2*hashsize+1] = {0x80};
  copy.add(std::span<const uint8_t>(zeroes, padsize));

  size_t len = msglength * 8;
  uint8_t msgsize[8];
  for (int n = 7; n >= 0; n--) {
    msgsize[n] = len & 0xFF;
    len >>= 8;
  }
  copy.add(std::span<const uint8_t>(msgsize, 8));
  std::vector<uint8_t> output;
  for (size_t i = 0; i < 8; i++) {
    for (size_t j = 0; j < sizeof(w[0]); j++) {
      output.push_back((copy.w[i] >> ((8*sizeof(w[0]) - 8 - 8*j))) & 0xFF);
    }
  }
  return output;
}

SHA512::SHA512() {
  w[0] = 0x6a09e667f3bcc908;
  w[1] = 0xbb67ae8584caa73b;
  w[2] = 0x3c6ef372fe94f82b;
  w[3] = 0xa54ff53a5f1d36f1;
  w[4] = 0x510e527fade682d1;
  w[5] = 0x9b05688c2b3e6c1f;
  w[6] = 0x1f83d9abfb41bd6b;
  w[7] = 0x5be0cd19137e2179;
}

void SHA512::add(std::span<const uint8_t> data) {
  size_t offset = msglength % (2*hashsize);
  size_t inoffset = 0;
  msglength += data.size();
  if (offset) {
    size_t copyNow = std::min(data.size(), 2*hashsize - offset);
    memcpy(chunk+offset, data.data(), copyNow);
    inoffset = copyNow;
    offset += copyNow;
    if (offset != 2*hashsize) {
      return;
    }
    processChunk();
    offset = 0;
  }
  while (data.size() - inoffset >= (2*hashsize)) {
    memcpy(chunk, data.data() + inoffset, 2*hashsize);
    processChunk();
    inoffset += 2*hashsize;
  }
  if (data.size() - inoffset)
    memcpy(chunk, data.data() + inoffset, data.size() - inoffset);
}

static uint64_t rotr64(uint64_t v, size_t count) {
  return (v >> count) | (v << (64 - count));
}

void SHA512::processChunk() {
  static const uint64_t K_512[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
  };
  uint64_t W[80];
  for (size_t t = 0; t < 16; t++) {
    W[t] = ((uint64_t)chunk[t*8] << 56) + 
           ((uint64_t)chunk[t*8+1] << 48) + 
           ((uint64_t)chunk[t*8+2] << 40) + 
           ((uint64_t)chunk[t*8+3] << 32) + 
           ((uint64_t)chunk[t*8+4] << 24) + 
           ((uint64_t)chunk[t*8+5] << 16) + 
           ((uint64_t)chunk[t*8+6] << 8) + 
           ((uint64_t)chunk[t*8+7] << 0);
  }
  for (size_t t = 16; t < 80; t++) {
    W[t] = (rotr64(W[t-2], 19) ^ rotr64(W[t-2], 61) ^ (W[t-2] >> 6)) + (rotr64(W[t-15], 1) ^ rotr64(W[t-15], 8) ^ (W[t-15] >> 7)) + W[t-7] + W[t-16];
  }

  uint64_t a = w[0], b = w[1], c = w[2], d = w[3], e = w[4], f = w[5], g = w[6], h = w[7];
  for (size_t t = 0; t < 80; t++) {
    uint64_t T1 = h + (rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)) + ((e & f) | (~e & g)) + K_512[t] + W[t];
    uint64_t T2 = (rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)) + ((a&b) ^ (a&c) ^ (b&c));
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }
  w[0] += a;
  w[1] += b;
  w[2] += c;
  w[3] += d;
  w[4] += e;
  w[5] += f;
  w[6] += g;
  w[7] += h;
}

SHA512::operator std::vector<uint8_t>() const {
  auto copy = *this;
  uint64_t padsize = 2*hashsize - ((msglength + 16) % (2*hashsize));
  uint8_t zeroes[2*hashsize+1] = {0x80};
  copy.add(std::span<const uint8_t>(zeroes, padsize));

  size_t len = msglength * 8;
  uint8_t msgsize[16];
  for (int n = 15; n >= 0; n--) {
    msgsize[n] = len & 0xFF;
    len >>= 8;
  }
  copy.add(std::span<const uint8_t>(msgsize, 16));
  std::vector<uint8_t> output;
  for (size_t i = 0; i < 8; i++) {
    for (size_t j = 0; j < sizeof(w[0]); j++) {
      output.push_back((copy.w[i] >> ((8*sizeof(w[0]) - 8 - 8*j))) & 0xFF);
    }
  }
  return output;
}

void SHA384::sha384_override() {
  w[0] = 0xcbbb9d5dc1059ed8;
  w[1] = 0x629a292a367cd507;
  w[2] = 0x9159015a3070dd17;
  w[3] = 0x152fecd8f70e5939;
  w[4] = 0x67332667ffc00b31;
  w[5] = 0x8eb44a8768581511;
  w[6] = 0xdb0c2e0d64f98fa7;
  w[7] = 0x47b5481dbefa4fa4;
}


