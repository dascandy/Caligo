#pragma once 

#include <cstddef>
#include <cstdint>
#include <vector>
#include <span>
#include <string>

namespace Caligo {

struct CRC32 {
  static constexpr size_t hashsize = 4;
  CRC32();
  template <typename... T>
  inline CRC32(T... ts)
  : CRC32()
  {
    (add(ts), ...);
  }
  inline void add(std::string_view str) {
    add(std::span<const uint8_t>((const uint8_t*)str.data(), str.size()));
  }
  void add(std::span<const uint8_t> data);
  operator std::array<uint8_t, hashsize>() const;
  inline std::array<uint8_t, hashsize> data() const { return *this; }
  operator std::string() const;
  static size_t MaxLength() {
    return (1ULL << 32) - 1;
  }
private:
  void processChunk();
  uint32_t h;
};

}

