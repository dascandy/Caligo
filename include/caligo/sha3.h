#pragma once 

#include <cstddef>
#include <cstdint>
#include <vector>
#include <span>

namespace Caligo {

template <size_t size>
struct SHA3 {
  static constexpr size_t hashsize = size/8;
  static constexpr size_t r = 1600 - 2 * size;
  SHA3();
  inline SHA3(std::span<const uint8_t> data)
  : SHA3()
  {
    add(data);
  }
  void add(std::span<const uint8_t> data);
  operator std::vector<uint8_t>() const;
  static inline std::vector<uint8_t> getAsn1Id();
  static size_t MaxLength() {
    return (1ULL << 61) - 1;
  }
private:
  void processChunk();
  uint64_t s[25];
  size_t msglength = 0;
};

}

