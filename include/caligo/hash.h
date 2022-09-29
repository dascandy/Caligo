#pragma once 

#include <cstddef>
#include <cstdint>
#include <vector>
#include <span>
#include <string_view>

namespace Caligo {

struct Hash {
  Hash(std::string_view hashName);
  template <typename... T>
  inline Hash(std::string_view hashName, T... ts)
  : Hash(hashName)
  {
    (add(ts), ...);
  }
  ~Hash();
  inline void add(std::string_view str) {
    add(std::span<const uint8_t>((const uint8_t*)str.data(), str.size()));
  }
  size_t hashsize();
  void add(std::span<const uint8_t> data);
  operator std::vector<uint8_t>() const;
  std::vector<uint8_t> data() const { return *this; }
  operator std::string() const;
  size_t MaxLength() const;
  std::vector<uint8_t> getAsn1Id();
private:
  struct Impl;
  std::unique_ptr<Impl> impl;
};

}

