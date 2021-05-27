#pragma once 

#include <cstddef>
#include <cstdint>
#include <vector>
#include <span>

namespace Caligo {

struct MD5 {
  static constexpr size_t hashsize = 16;
  MD5();
  inline MD5(std::span<const uint8_t> data)
  : MD5()
  {
    add(data);
  }
  void add(std::span<const uint8_t> data);
  operator std::vector<uint8_t>() const;
  static size_t MaxLength() {
    return (1ULL << 61) - 1;
  }
private:
  void processChunk();
  uint8_t chunk[64];
  uint32_t h[4];
  size_t msglength = 0;
};

}

