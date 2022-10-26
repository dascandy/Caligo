#include <catch2/catch_all.hpp>
#include <caligo/crc.h>

namespace Caligo {

TEST_CASE("CRC32 sanity check", "[CRC32]") {
  std::array<uint8_t,4> s1 = CRC32(std::span<uint8_t>((unsigned char*)"The quick brown fox jumps over the lazy dog", 43));
  std::array<uint8_t,4> s1t = { 0x41, 0x4f, 0xa3, 0x39 };
  CHECK(s1 == s1t);

  std::array<uint8_t,4> s2 = CRC32(std::span<uint8_t>((unsigned char*)"The quick brown fox jumps over the lazy dog.", 44));
  std::array<uint8_t,4> s2t = { 0x51, 0x90, 0x25, 0xe9 };
  CHECK(s2 == s2t);

  std::array<uint8_t,4> s3 = CRC32(std::span<uint8_t>((unsigned char*)"", (int)0));
  std::array<uint8_t,4> s3t = { 0x00, 0x00, 0x00, 0x00 };
  CHECK(s3 == s3t);
}

}

