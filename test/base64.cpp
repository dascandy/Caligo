#include <catch/catch.hpp>
#include <caligo/base64.h>

TEST_CASE("base64 encoding and decoding", "[BASE64]") {
  std::string text = "The quick brown fox jumps over the lazy dog";
  std::span<const uint8_t> range((const uint8_t*)text.data(), text.size());
  std::string b64text = base64(range);
  std::vector<uint8_t> r2 = base64d(b64text);
  std::string text2((const char*)r2.data(), r2.size());
  REQUIRE(text == text2);
}


