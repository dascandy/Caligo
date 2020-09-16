#pragma once

#include <vector>
#include <cstdint>

template <typename Cipher>
struct key_iv_pair {
  std::vector<uint8_t> key;
  std::vector<uint8_t> iv;
};


