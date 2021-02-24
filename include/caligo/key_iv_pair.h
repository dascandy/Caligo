#pragma once

#include <vector>
#include <cstdint>

namespace Caligo {

template <typename Cipher>
struct key_iv_pair {
  std::vector<uint8_t> key;
  std::vector<uint8_t> iv;
};

}

