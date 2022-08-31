#include "caligo/sha3.h"
#include <stdio.h>

template <size_t size>
Caligo::SHA3<size>::SHA3() 
: s()
{
}

template <size_t size>
void Caligo::SHA3<size>::add(std::span<const uint8_t> data) {
  size_t chunksize = r/8;
  size_t offset = msglength % (r / 8);

  for (auto& c : data) {
    s[offset / 8] ^= ((uint64_t)c << ((offset % 8) * 8));
    offset++;
    if (offset == chunksize) {
      processChunk();
      offset = 0;
    }
  }
  msglength += data.size();
}

template <size_t size>
Caligo::SHA3<size>::operator std::array<uint8_t,hashsize>() const {
  SHA3<size> copy = *this;
  size_t chunksize = r/8;
  size_t offset = msglength % (r / 8);
  copy.s[offset / 8] ^= ((uint64_t)0x06 << ((offset % 8) * 8));
  copy.s[(chunksize / 8) - 1] ^= 0x8000000000000000ULL;
  copy.processChunk();
  std::array<uint8_t, hashsize> rv;
  for (size_t n = 0; n < size/8; n++) {
    rv[n] = (copy.s[n / 8] >> (8 * (n % 8)));
  }
  return rv;
}
template <size_t size>
Caligo::SHA3<size>::operator std::string() const {
  static const char hextab[] = "0123456789abcdef";
  std::string str;
  for (const auto& c : data()) {
    str.push_back(hextab[c >> 4]);
    str.push_back(hextab[c & 0xF]);
  }
  return str;
}


template <size_t size>
void Caligo::SHA3<size>::processChunk() {
  static const constexpr uint64_t SHA3RoundConstants[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A, 
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A, 
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008, 
  };
  // Please don't blame me for these horrible greek letters describing the algorithm.
  for (size_t round = 0; round < 24; round++) {
    // theta
    uint64_t c[5], d[5];
    for(size_t x=0; x<5; x++) {
        c[x] = 0; 
        for(size_t y=0; y<5; y++) 
            c[x] ^= s[y*5+x];
    }

    for(size_t x=0; x<5; x++)
        d[x] = (c[(x+1)%5] << 1) ^ (c[(x+1)%5] >> 63) ^ c[(x+4)%5];

    for(size_t x=0; x<5; x++) {
        s[x] ^= d[x];
        s[x+5] ^= d[x];
        s[x+10] ^= d[x];
        s[x+15] ^= d[x];
        s[x+20] ^= d[x];
    }

    // rho & pi
    int64_t t = (s[3] << 28) | (s[3] >> 36);
    s[3] = (s[18] << 21) | (s[18] >> 43);
    s[18] = (s[17] << 15) | (s[17] >> 49);
    s[17] = (s[11] << 10) | (s[11] >> 54);
    s[11] = (s[7] << 6) | (s[7] >> 58);
    s[7] = (s[10] << 3) | (s[10] >> 61);
    s[10] = (s[1] << 1) | (s[1] >> 63);
    s[1] = (s[6] << 44) | (s[6] >> 20);
    s[6] = (s[9] << 20) | (s[9] >> 44);
    s[9] = (s[22] << 61) | (s[22] >> 3);
    s[22] = (s[14] << 39) | (s[14] >> 25);
    s[14] = (s[20] << 18) | (s[20] >> 46);
    s[20] = (s[2] << 62) | (s[2] >> 2);
    s[2] = (s[12] << 43) | (s[12] >> 21);
    s[12] = (s[13] << 25) | (s[13] >> 39);
    s[13] = (s[19] << 8) | (s[19] >> 56);
    s[19] = (s[23] << 56) | (s[23] >> 8);
    s[23] = (s[15] << 41) | (s[15] >> 23);
    s[15] = (s[4] << 27) | (s[4] >> 37);
    s[4] = (s[24] << 14) | (s[24] >> 50);
    s[24] = (s[21] << 2) | (s[21] >> 62);
    s[21] = (s[8] << 55) | (s[8] >> 9);
    s[8] = (s[16] << 45) | (s[16] >> 19);
    s[16] = (s[5] << 36) | (s[5] >> 28);
    s[5] = t;

    // chi
    for(size_t y=0; y<5; y++) { 
        uint64_t c[5];
        for(size_t x=0; x<5; x++)
            c[x] = s[y*5+x] ^ (~s[5*y + ((x+1)%5)] & s[5*y + ((x+2)%5)]);
        for(size_t x=0; x<5; x++)
            s[y*5+x] = c[x];
    }

    // iota
    s[0] ^= SHA3RoundConstants[round];
  }
}

template <>
std::vector<uint8_t> Caligo::SHA3<224>::getAsn1Id() {
  return std::initializer_list<uint8_t>{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x20 };
}

template <>
std::vector<uint8_t> Caligo::SHA3<256>::getAsn1Id() {
  return std::initializer_list<uint8_t>{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20 };
}

template <>
std::vector<uint8_t> Caligo::SHA3<384>::getAsn1Id() {
  return std::initializer_list<uint8_t>{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x20 };
}

template <>
std::vector<uint8_t> Caligo::SHA3<512>::getAsn1Id() {
  return std::initializer_list<uint8_t>{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x00, 0x04, 0x20 };
}

template struct Caligo::SHA3<224>;
template struct Caligo::SHA3<256>;
template struct Caligo::SHA3<384>;
template struct Caligo::SHA3<512>;


