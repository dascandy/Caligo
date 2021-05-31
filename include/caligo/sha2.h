#pragma once 

#include <cstddef>
#include <cstdint>
#include <vector>
#include <span>
#include <string>

namespace Caligo {

template <size_t bits>
struct SHA2;

template <>
struct SHA2<256> {
  static constexpr size_t hashsize = 32;
  SHA2();
  inline SHA2(std::span<const uint8_t> data)
  : SHA2()
  {
    add(data);
  }
  inline SHA2(std::string_view str)
  : SHA2(std::span<const uint8_t>((const uint8_t*)str.data(), str.size()))
  {
  }
  void add(std::span<const uint8_t> data);
  operator std::vector<uint8_t>() const;
  operator std::string() const;
  static inline std::vector<uint8_t> getAsn1Id() {
    return std::initializer_list<uint8_t>{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
  }
  static size_t MaxLength() {
    return (1ULL << 61) - 1;
  }
private:
  void processChunk();
  uint8_t chunk[hashsize*2];
  uint32_t w[8];
  size_t msglength = 0;
};

template <>
struct SHA2<512> {
  static constexpr size_t hashsize = 64;
  SHA2();
  inline SHA2(std::span<const uint8_t> data)
  : SHA2()
  {
    add(data);
  }
  inline SHA2(std::string_view str)
  : SHA2(std::span<const uint8_t>((const uint8_t*)str.data(), str.size()))
  {
  } 
  void add(std::span<const uint8_t> data);
  operator std::vector<uint8_t>() const; 
  operator std::string() const;
  static inline std::vector<uint8_t> getAsn1Id() {
    return std::initializer_list<uint8_t>{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };
  }
  static size_t MaxLength() {
    return (1ULL << 61) - 1;
  }
protected:
  void processChunk();
  uint8_t chunk[hashsize*2];
  uint64_t w[8];
  size_t msglength = 0;
};

template <>
struct SHA2<384> : private SHA2<512> {
  static constexpr size_t hashsize = 48;
  inline SHA2() {
    sha384_override();
  }
  inline SHA2(std::span<const uint8_t> data)
  : SHA2<512>()
  {
    sha384_override();
    add(data);
  }
  inline SHA2(std::string_view str)
  : SHA2(std::span<const uint8_t>((const uint8_t*)str.data(), str.size()))
  {
  } 
  void sha384_override();
  inline operator std::vector<uint8_t>() const {
    std::vector<uint8_t> hash = *((SHA2<512>*)this);
    hash.resize(hashsize);
    return hash;
  }
  operator std::string() const;
  using SHA2<512>::add;
  static inline std::vector<uint8_t> getAsn1Id() {
    return std::initializer_list<uint8_t>{ 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };
  }
  static size_t MaxLength() {
    return (1ULL << 61) - 1;
  }
};

}

