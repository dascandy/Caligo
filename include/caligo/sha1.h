#pragma once 

#include <cstddef>
#include <cstdint>
#include <vector>
#include <span>
#include <string>

namespace Caligo {

struct SHA1 {
  static constexpr size_t hashsize = 20;
  SHA1();
  inline SHA1(std::string_view str)
  : SHA1(std::span<const uint8_t>((const uint8_t*)str.data(), str.size()))
  { 
  }
  inline SHA1(std::span<const uint8_t> data)
  : SHA1()
  {
    add(data);
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
  uint8_t chunk[64];
  uint32_t h[5];
  size_t msglength = 0;
};

}

