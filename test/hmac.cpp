#include <catch2/catch.hpp>
#include <caligo/hkdf.h>
#include <caligo/sha2.h>

namespace Caligo {

TEST_CASE("hmac basic test", "[HMAC]") {
  std::vector<uint8_t> key = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
  std::vector<uint8_t> text = { 0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65 };
  std::array<uint8_t,32> hash = HMAC<SHA2<256>>(text, key);
  std::array<uint8_t,32> test_hash = { 0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7 };
  REQUIRE(hash == test_hash);
}

}

