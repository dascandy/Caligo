#pragma once 

#include <cstddef>
#include <cstdint>
#include <vector>
#include <span>
#include <string>

namespace Caligo {

template <size_t size>
struct SHA3 {
  static constexpr size_t hashsize = size/8;
  static constexpr size_t r = 1600 - 2 * size;
  SHA3();
  template <typename... T>
  inline SHA3(T... ts)
  : SHA3()
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
    if constexpr (size == 224) {
      return std::initializer_list<uint8_t>{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x20 };
    } else if constexpr (size == 256) {
      return std::initializer_list<uint8_t>{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20 };
    } else if constexpr (size == 384) {
      return std::initializer_list<uint8_t>{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x20 };
    } else if constexpr (size == 512) {
      return std::initializer_list<uint8_t>{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x00, 0x04, 0x20 };
    } else {
      return {};
    }
  }
private:
  void processChunk();
  uint64_t s[25];
  size_t msglength = 0;
};

}

