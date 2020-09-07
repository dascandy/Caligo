#pragma once 

#include <cstddef>
#include <vector>
#include <span>

/*
    id-sha256  OBJECT IDENTIFIER  ::=  { joint-iso-itu-t(2)
                         country(16) us(840) organization(1) gov(101)
                         csor(3) nistalgorithm(4) hashalgs(2) 1 }
    id-sha384  OBJECT IDENTIFIER  ::=  { joint-iso-itu-t(2)
                         country(16) us(840) organization(1) gov(101)
                         csor(3) nistalgorithm(4) hashalgs(2) 2 }
    id-sha512  OBJECT IDENTIFIER  ::=  { joint-iso-itu-t(2)
                         country(16) us(840) organization(1) gov(101)
                         csor(3) nistalgorithm(4) hashalgs(2) 3 }
                         */
struct SHA256 {
  static constexpr size_t hashsize = 32;
  SHA256();
  SHA256(std::span<const uint8_t> data)
  : SHA256()
  {
    add(data);
  }
  void add(std::span<const uint8_t> data);
  operator std::vector<uint8_t>() const;
private:
  void processChunk();
  uint8_t chunk[hashsize*2];
  uint32_t w[8];
  size_t msglength = 0;
};

struct SHA512 {
  static constexpr size_t hashsize = 64;
  SHA512();
  SHA512(std::span<const uint8_t> data)
  : SHA512()
  {
    add(data);
  }
  void add(std::span<const uint8_t> data);
  operator std::vector<uint8_t>() const; 
protected:
  void processChunk();
  uint8_t chunk[hashsize*2];
  uint64_t w[8];
  size_t msglength = 0;
};
struct SHA384 : SHA512 {
  static constexpr size_t hashsize = 48;
  SHA384() {
    sha384_override();
  }
  SHA384(std::span<const uint8_t> data)
  {
    sha384_override();
    add(data);
  }
  void sha384_override();
  inline operator std::vector<uint8_t>() const {
    std::vector<uint8_t> hash = *((SHA512*)this);
    hash.resize(hashsize);
    return hash;
  }
};
