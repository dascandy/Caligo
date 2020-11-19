#include <catch/catch.hpp>
#include <caligo/hkdf.h>
#include <caligo/sha.h>

TEST_CASE("SHA sanity check", "[SHA]") {
  char grape[] = "grape";
  std::vector<uint8_t> grape_hash = { 0x0f, 0x78, 0xfc, 0xc4, 0x86, 0xf5, 0x31, 0x54, 0x18, 0xfb, 0xf0, 0x95, 0xe7, 0x1c, 0x06, 0x75, 0xee, 0x07, 0xd3, 0x18, 0xe5, 0xac, 0x4d, 0x15, 0x00, 0x50, 0xcd, 0x8e, 0x57, 0x96, 0x64, 0x96};
  std::vector<uint8_t> grape_h = SHA<256>(std::span<uint8_t>((unsigned char*)grape, 5));
  CHECK(grape_h == grape_hash);


  std::vector<uint8_t> s1 = SHA<256>();
  std::vector<uint8_t> s1t = { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };
  CHECK(s1 == s1t);
}

TEST_CASE("SHA1 sanity check", "[SHA]") {
  std::vector<uint8_t> abc_hash = { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d };
  std::vector<uint8_t> abc_h = SHA<1>(std::span<uint8_t>((unsigned char*)"abc", 3));
  CHECK(abc_hash == abc_h);

  std::vector<uint8_t> s1 = SHA<1>();
  std::vector<uint8_t> s1t = { 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09 };
  CHECK(s1 == s1t);

  std::vector<uint8_t> qbfd_hash = { 0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12 }; 
  std::vector<uint8_t> qbfd_h = SHA<1>(std::span<uint8_t>((unsigned char*)"The quick brown fox jumps over the lazy dog", 43));
  CHECK(qbfd_hash == qbfd_h);

  std::vector<uint8_t> qbfc_hash = { 0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a, 0xfa, 0xd3, 0xe8, 0x5a, 0x0b, 0xd1, 0x7d, 0x9b, 0x10, 0x0d, 0xb4, 0xb3 };
  std::vector<uint8_t> qbfc_h = SHA<1>(std::span<uint8_t>((unsigned char*)"The quick brown fox jumps over the lazy cog", 43));
  CHECK(qbfc_hash == qbfc_h);
}

TEST_CASE("SHA512", "[SHA]") {
  std::vector<uint8_t> s3 = SHA<512>();
  std::vector<uint8_t> s3t = { 0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e };
  CHECK(s3 == s3t);
  std::vector<uint8_t> s2 = SHA<384>();
  std::vector<uint8_t> s2t = { 0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b };
  CHECK(s2 == s2t);
}
