#pragma once

#include <vector>
#include <cstdint>

namespace Caligo {

template <typename Cipher>
struct key_iv_pair {
  key_iv_pair(std::span<const uint8_t> in_key, std::span<const uint8_t> in_iv) {
    key.resize(in_key.size());
    key.assign(in_key.begin(), in_key.end());
    iv.resize(in_iv.size());
    iv.assign(in_iv.begin(), in_iv.end());
  }
  key_iv_pair(std::initializer_list<uint8_t> in_key, std::initializer_list<uint8_t> in_iv) {
    key.resize(in_key.size());
    key.assign(in_key.begin(), in_key.end());
    iv.resize(in_iv.size());
    iv.assign(in_iv.begin(), in_iv.end());
  }
  std::vector<uint8_t> key;
  std::vector<uint8_t> iv;
};

}

