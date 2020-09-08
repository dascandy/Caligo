#pragma once 

#include <cstddef>
#include <cstdint>
#include <s2/vector>
#include <s2/span>

struct SHA256 {
  static constexpr size_t hashsize = 32;
  SHA256();
  inline SHA256(s2::span<const uint8_t> data)
  : SHA256()
  {
    add(data);
  }
  void add(s2::span<const uint8_t> data);
  operator s2::vector<uint8_t>() const;
  inline s2::span<const uint8_t> getAsn1Id() {
    return { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
  }
private:
  void processChunk();
  uint8_t chunk[hashsize*2];
  uint32_t w[8];
  size_t msglength = 0;
};

struct SHA512 {
  static constexpr size_t hashsize = 64;
  SHA512();
  inline SHA512(s2::span<const uint8_t> data)
  : SHA512()
  {
    add(data);
  }
  void add(s2::span<const uint8_t> data);
  operator s2::vector<uint8_t>() const; 
  inline s2::span<const uint8_t> getAsn1Id() {
    return { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };
  }
protected:
  void processChunk();
  uint8_t chunk[hashsize*2];
  uint64_t w[8];
  size_t msglength = 0;
};

struct SHA384 : SHA512 {
  static constexpr size_t hashsize = 48;
  inline SHA384() {
    sha384_override();
  }
  inline SHA384(s2::span<const uint8_t> data)
  : SHA512()
  {
    sha384_override();
    add(data);
  }
  void sha384_override();
  inline operator s2::vector<uint8_t>() const {
    s2::vector<uint8_t> hash = *((SHA512*)this);
    hash.resize(hashsize);
    return hash;
  }
  inline s2::span<const uint8_t> getAsn1Id() {
    return { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };
  }
};


