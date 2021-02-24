#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace Caligo {

extern std::vector<uint64_t> testValues;

inline uint64_t generate_random_value() {
  if (!testValues.empty()) {
    uint64_t value = testValues.back();
    testValues.pop_back();
    return value;
  }
  // LCG, using only the major 32 bits to have high enough entropy in those. Still a PRNG.
  static const uint64_t A = 6364136223846793005;
  static const uint64_t C = 1442695040888963407;
  static uint64_t cval = 0xa9782365ba09625b;
#ifdef PLATFORM_HAS_RDSEED
  uint64_t value;
  asm volatile ("rdseed" :: "=a"(value));
  cval ^= (value & 0xFFFFFFFF);
#endif
  cval = (cval * A) + C;
  uint64_t rv = (cval) & 0xFFFFFFFF00000000ULL;
#ifdef PLATFORM_HAS_RDSEED
  cval ^= (value >> 32);
#endif
  cval = (cval * A) + C;
  rv |= (cval >> 32) & 0xFFFFFFFF;
  return rv;
}

inline void generate_random(std::span<uint64_t> target) {
  for (size_t n = 0; n < target.size(); n++) {
    target[n] = generate_random_value();
  }
}

inline void generate_random(std::span<uint32_t> target) {
  for (size_t n = 0; n < target.size(); n += 2) {
    uint64_t value = generate_random_value();
    for (size_t i = 0; i < 2; i++) {
      if (i + n == target.size()) break;
      target[i + n] = value & 0xFFFFFFFFU;
      value >>= 32;
    }
  }
}

inline void generate_random(std::span<uint16_t> target) {
  for (size_t n = 0; n < target.size(); n += 4) {
    uint64_t value = generate_random_value();
    for (size_t i = 0; i < 4; i++) {
      if (i + n == target.size()) break;
      target[i + n] = value & 0xFFFF;
      value >>= 16;
    }
  }
}

inline void generate_random(std::span<uint8_t> target) {
  for (size_t n = 0; n < target.size(); n += 8) {
    uint64_t value = generate_random_value();
    for (size_t i = 0; i < 8; i++) {
      if (i + n == target.size()) break;
      target[i + n] = value & 0xFF;
      value >>= 8;
    }
  }
}

}
