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
  template <typename... T>
  inline SHA1(T... ts)
  : SHA1()
  {
    (add(ts), ...);
  }
  inline void add(std::string_view str) {
    add(std::span<const uint8_t>((const uint8_t*)str.data(), str.size()));
  }
  void add(std::span<const uint8_t> data);
  operator std::array<uint8_t, hashsize>() const;
  std::array<uint8_t, hashsize> data() const { return *this; }
  operator std::string() const;
  static inline std::vector<uint8_t> getAsn1Id() {
    return std::initializer_list<uint8_t>{ 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
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

