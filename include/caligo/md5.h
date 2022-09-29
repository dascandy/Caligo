#pragma once 

#include <cstddef>
#include <cstdint>
#include <vector>
#include <span>
#include <string>

namespace Caligo {

struct MD5 {
  static constexpr size_t hashsize = 16;
  MD5();
  template <typename... T>
  inline MD5(T... ts)
  : MD5()
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
  static size_t MaxLength() {
    return (1ULL << 61) - 1;
  }
  static inline std::vector<uint8_t> getAsn1Id() {
    return std::initializer_list<uint8_t>{ 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
  }
private:
  void processChunk();
  uint8_t chunk[64];
  uint32_t h[4];
  size_t msglength = 0;
};

}

