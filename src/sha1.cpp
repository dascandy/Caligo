#include "caligo/sha1.h"
#include <cstdio>

namespace Caligo {

SHA1::SHA1() {
  h[0] = 0x67452301;
  h[1] = 0xefcdab89;
  h[2] = 0x98badcfe;
  h[3] = 0x10325476;
  h[4] = 0xc3d2e1f0;
}

void SHA1::add(std::span<const uint8_t> data) {
  size_t offset = msglength % 64;
  size_t inoffset = 0;
  msglength += data.size();
  if (offset) {
    size_t copyNow = std::min(data.size(), 64 - offset);
    memcpy(chunk+offset, data.data(), copyNow);
    inoffset = copyNow;
    offset += copyNow;
    if (offset != 64) {
      return;
    }
    processChunk();
    offset = 0;
  }
  while (data.size() - inoffset >= 64) {
    memcpy(chunk, data.data() + inoffset, 64);
    processChunk();
    inoffset += 64;
  }
  if (data.size() - inoffset)
    memcpy(chunk, data.data() + inoffset, data.size() - inoffset);
}

SHA1::operator std::array<uint8_t,20>() const {
  auto copy = *this;
  uint64_t padsize = 64 - ((msglength + 8) % (64));
  uint8_t zeroes[64+1] = {0x80};
  copy.add(std::span<const uint8_t>(zeroes, padsize));

  size_t len = msglength * 8;
  uint8_t msgsize[8];
  for (int n = 7; n >= 0; n--) {
    msgsize[n] = len & 0xFF;
    len >>= 8;
  }
  copy.add(std::span<const uint8_t>(msgsize, 8));
  std::array<uint8_t,20> output;
  for (size_t i = 0; i < 5; i++) {
    for (size_t j = 0; j < sizeof(h[0]); j++) {
      output[j+4*i] = ((copy.h[i] >> ((8*sizeof(h[0]) - 8 - 8*j))) & 0xFF);
    }
  }
  return output;
}

SHA1::operator std::string() const {
  static const char hextab[] = "0123456789abcdef";
  std::string str;
  for (const auto& c : data()) {
    str.push_back(hextab[c >> 4]);
    str.push_back(hextab[c & 0xF]);
  }
  return str;
}

static uint32_t rotate(uint32_t value, int left) {
  return (value << left) ^ (value >> (32 - left)); 
}

void SHA1::processChunk() {
  uint32_t w[80];
  for (size_t n = 0; n < 16; n++) {
    uint32_t v = 0;
    for (size_t i = 0; i < 4; i++) {
      v = (v << 8) | chunk[4*n+i];
    }
    w[n] = v;
  }
  for (size_t i = 16; i < 80; i++) {
    w[i] = rotate((w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]), 1);
  }
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
  for (size_t i = 0; i < 20; i++) {
    uint32_t t = rotate(a, 5) + ((b & c) | (~b & d)) + e + w[i] + 0x5A827999;
    e = d; d = c; c = rotate(b, 30); b = a; a = t;
  }
  for (size_t i = 20; i < 40; i++) {
    uint32_t t = rotate(a, 5) + (b ^ c ^ d) + e + w[i] + 0x6ED9EBA1;
    e = d; d = c; c = rotate(b, 30); b = a; a = t;
  }
  for (size_t i = 40; i < 60; i++) {
    uint32_t t = rotate(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[i] + 0x8F1BBCDC;
    e = d; d = c; c = rotate(b, 30); b = a; a = t;
  }
  for (size_t i = 60; i < 80; i++) {
    uint32_t t = rotate(a, 5) + (b ^ c ^ d) + e + w[i] + 0xCA62C1D6;
    e = d; d = c; c = rotate(b, 30); b = a; a = t;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}
}


