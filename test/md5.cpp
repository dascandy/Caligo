#include <catch2/catch.hpp>
#include <caligo/md5.h>

namespace Caligo {

TEST_CASE("MD5 sanity check", "[MD5]") {
  std::vector<uint8_t> s1 = MD5(std::span<uint8_t>((unsigned char*)"The quick brown fox jumps over the lazy dog", 43));
  std::vector<uint8_t> s1t = { 0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6 };
  CHECK(s1 == s1t);

  std::vector<uint8_t> s2 = MD5(std::span<uint8_t>((unsigned char*)"The quick brown fox jumps over the lazy dog.", 44));
  std::vector<uint8_t> s2t = { 0xe4, 0xd9, 0x09, 0xc2, 0x90, 0xd0, 0xfb, 0x1c, 0xa0, 0x68, 0xff, 0xad, 0xdf, 0x22, 0xcb, 0xd0 };
  CHECK(s2 == s2t);

  std::vector<uint8_t> s3 = MD5(std::span<uint8_t>((unsigned char*)"", (int)0));
  std::vector<uint8_t> s3t = { 0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e };
  CHECK(s3 == s3t);
}

}
