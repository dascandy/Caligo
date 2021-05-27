#include "caligo/md5.h"
#include <cstdio>

namespace Caligo {

MD5::MD5() {
  h[0] = 0x67452301;
  h[1] = 0xefcdab89;
  h[2] = 0x98badcfe;
  h[3] = 0x10325476;
}

static uint32_t K[64] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static uint8_t s[64] = {
  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22 ,
  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23 ,
  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 ,
};

void MD5::add(std::span<const uint8_t> data) {
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

MD5::operator std::vector<uint8_t>() const {
  auto copy = *this;
  uint64_t padsize = 64 - ((msglength + 8) % (64));
  uint8_t zeroes[64+1] = {0x80};
  copy.add(std::span<const uint8_t>(zeroes, padsize));

  size_t len = msglength * 8;
  uint8_t msgsize[8];
  for (int n = 0; n < 8; n++) {
    msgsize[n] = len & 0xFF;
    len >>= 8;
  }
  copy.add(std::span<const uint8_t>(msgsize, 8));
  std::vector<uint8_t> output;
  for (size_t i = 0; i < 4; i++) {
    for (size_t j = 0; j < sizeof(h[0]); j++) {
      output.push_back((copy.h[i] >> (8*j)) & 0xFF);
    }
  }
  return output;
}

static uint32_t rotate(uint32_t value, int left) {
  return (value << left) ^ (value >> (32 - left)); 
}

void MD5::processChunk() {
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
  for (size_t i = 0; i < 64; i++) {
    uint32_t f, g;
    if (i < 16) {
      f = (b & c) | ((~b) & d);
      g = i;
    } else if (i < 32) {
      f = (d & b) | ((~d) & c);
      g = (5 * i + 1) % 16;
    } else if (i < 48) {
      f = b ^ c ^ d;
      g = (3 * i + 5) % 16;
    } else {
      f = c ^ (b | (~d));
      g = (7 * i) % 16;
    }

    uint32_t msgword = chunk[4*g] | (chunk[4*g+1] << 8) | (chunk[4*g+2] << 16) | ((uint32_t)chunk[4*g+3] << 24);
//    uint32_t msgword = chunk[4*g+3] | (chunk[4*g+2] << 8) | (chunk[4*g+1] << 16) | ((uint32_t)chunk[4*g] << 24);
    f = f + a + K[i] + msgword;
    a = d;
    d = c;
    c = b;
    b = b + rotate(f, s[i]);
  }

  h[0] += a; h[1] += b; h[2] += c; h[3] += d;
}

}

