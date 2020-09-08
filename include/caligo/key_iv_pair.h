#pragma once

#include <s2/vector>
#include <cstdint>

template <typename Cipher>
struct key_iv_pair {
  s2::vector<uint8_t> key;
  s2::vector<uint8_t> iv;
};


