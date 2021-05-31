#include <catch2/catch.hpp>
#include <caligo/hkdf.h>
#include <caligo/sha1.h>
#include <caligo/sha2.h>
#include <caligo/sha3.h>

namespace Caligo {

TEST_CASE("SHA sanity check", "[SHA]") {
  char grape[] = "grape";
  std::vector<uint8_t> grape_hash = { 0x0f, 0x78, 0xfc, 0xc4, 0x86, 0xf5, 0x31, 0x54, 0x18, 0xfb, 0xf0, 0x95, 0xe7, 0x1c, 0x06, 0x75, 0xee, 0x07, 0xd3, 0x18, 0xe5, 0xac, 0x4d, 0x15, 0x00, 0x50, 0xcd, 0x8e, 0x57, 0x96, 0x64, 0x96};
  std::vector<uint8_t> grape_h = SHA2<256>(std::span<uint8_t>((unsigned char*)grape, 5));
  CHECK(grape_h == grape_hash);


  std::vector<uint8_t> s1 = SHA2<256>();
  std::vector<uint8_t> s1t = { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };
  CHECK(s1 == s1t);
}

TEST_CASE("SHA1 sanity check", "[SHA]") {
  std::vector<uint8_t> abc_hash = { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d };
  std::vector<uint8_t> abc_h = SHA1(std::span<uint8_t>((unsigned char*)"abc", 3));
  CHECK(abc_hash == abc_h);

  std::vector<uint8_t> s1 = SHA1();
  std::vector<uint8_t> s1t = { 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09 };
  CHECK(s1 == s1t);

  std::vector<uint8_t> qbfd_hash = { 0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12 }; 
  std::vector<uint8_t> qbfd_h = SHA1(std::span<uint8_t>((unsigned char*)"The quick brown fox jumps over the lazy dog", 43));
  CHECK(qbfd_hash == qbfd_h);

  std::vector<uint8_t> qbfc_hash = { 0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a, 0xfa, 0xd3, 0xe8, 0x5a, 0x0b, 0xd1, 0x7d, 0x9b, 0x10, 0x0d, 0xb4, 0xb3 };
  std::vector<uint8_t> qbfc_h = SHA1(std::span<uint8_t>((unsigned char*)"The quick brown fox jumps over the lazy cog", 43));
  CHECK(qbfc_hash == qbfc_h);
}

TEST_CASE("SHA512", "[SHA]") {
  std::vector<uint8_t> s3 = SHA2<512>();
  std::vector<uint8_t> s3t = { 0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e };
  CHECK(s3 == s3t);
  std::vector<uint8_t> s2 = SHA2<384>();
  std::vector<uint8_t> s2t = { 0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b };
  CHECK(s2 == s2t);
}

template <typename Hash>
void Check(const char* teststr, std::vector<uint8_t> hash) {
  std::vector<uint8_t> output = Hash(std::span<const uint8_t>((const uint8_t*)teststr, (const uint8_t*)teststr + strlen(teststr)));
  CHECK(output == hash);
}

TEST_CASE("Test vectors", "[SHA]") {
  Check<SHA1>("abc", { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d, });
  Check<SHA1>("", { 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09, });
  Check<SHA1>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", { 0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1, });
  Check<SHA1>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", { 0xa4, 0x9b, 0x24, 0x46, 0xa0, 0x2c, 0x64, 0x5b, 0xf4, 0x19, 0xf9, 0x95, 0xb6, 0x70, 0x91, 0x25, 0x3a, 0x04, 0xa2, 0x59, });

//  Check<SHA2<224>>("abc", { 0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7, });
  Check<SHA2<256>>("abc", { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad, });
  Check<SHA2<384>>("abc", { 0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7, });
  Check<SHA2<512>>("abc", { 0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f, });
//  Check<SHA2<224>>("", { 0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4, 0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4, 0x2f, });
  Check<SHA2<256>>("", { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55, });
  Check<SHA2<384>>("", { 0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b, });
  Check<SHA2<512>>("", { 0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e, });
//  Check<SHA2<224>>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", { 0x75, 0x38, 0x8b, 0x16, 0x51, 0x27, 0x76, 0xcc, 0x5d, 0xba, 0x5d, 0xa1, 0xfd, 0x89, 0x01, 0x50, 0xb0, 0xc6, 0x45, 0x5c, 0xb4, 0xf5, 0x8b, 0x19, 0x52, 0x52, 0x25, 0x25, });
  Check<SHA2<256>>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1, });
  Check<SHA2<384>>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", { 0x33, 0x91, 0xfd, 0xdd, 0xfc, 0x8d, 0xc7, 0x39, 0x37, 0x07, 0xa6, 0x5b, 0x1b, 0x47, 0x09, 0x39, 0x7c, 0xf8, 0xb1, 0xd1, 0x62, 0xaf, 0x05, 0xab, 0xfe, 0x8f, 0x45, 0x0d, 0xe5, 0xf3, 0x6b, 0xc6, 0xb0, 0x45, 0x5a, 0x85, 0x20, 0xbc, 0x4e, 0x6f, 0x5f, 0xe9, 0x5b, 0x1f, 0xe3, 0xc8, 0x45, 0x2b, });
  Check<SHA2<512>>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", { 0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a, 0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16, 0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8, 0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35, 0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9, 0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0, 0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03, 0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45, });
//  Check<SHA2<224>>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", { 0xc9, 0x7c, 0xa9, 0xa5, 0x59, 0x85, 0x0c, 0xe9, 0x7a, 0x04, 0xa9, 0x6d, 0xef, 0x6d, 0x99, 0xa9, 0xe0, 0xe0, 0xe2, 0xab, 0x14, 0xe6, 0xb8, 0xdf, 0x26, 0x5f, 0xc0, 0xb3, });
  Check<SHA2<256>>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", { 0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37, 0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1, });
  Check<SHA2<384>>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", { 0x09, 0x33, 0x0c, 0x33, 0xf7, 0x11, 0x47, 0xe8, 0x3d, 0x19, 0x2f, 0xc7, 0x82, 0xcd, 0x1b, 0x47, 0x53, 0x11, 0x1b, 0x17, 0x3b, 0x3b, 0x05, 0xd2, 0x2f, 0xa0, 0x80, 0x86, 0xe3, 0xb0, 0xf7, 0x12, 0xfc, 0xc7, 0xc7, 0x1a, 0x55, 0x7e, 0x2d, 0xb9, 0x66, 0xc3, 0xe9, 0xfa, 0x91, 0x74, 0x60, 0x39, });
  Check<SHA2<512>>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", { 0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f, 0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18, 0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a, 0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09, });

  Check<SHA3<224>>("abc", { 0xe6, 0x42, 0x82, 0x4c, 0x3f, 0x8c, 0xf2, 0x4a, 0xd0, 0x92, 0x34, 0xee, 0x7d, 0x3c, 0x76, 0x6f, 0xc9, 0xa3, 0xa5, 0x16, 0x8d, 0x0c, 0x94, 0xad, 0x73, 0xb4, 0x6f, 0xdf, });
  Check<SHA3<256>>("abc", { 0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32, });
  Check<SHA3<384>>("abc", { 0xec, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6f, 0xc9, 0x26, 0x45, 0x9f, 0x58, 0xe2, 0xc6, 0xad, 0x8d, 0xf9, 0xb4, 0x73, 0xcb, 0x0f, 0xc0, 0x8c, 0x25, 0x96, 0xda, 0x7c, 0xf0, 0xe4, 0x9b, 0xe4, 0xb2, 0x98, 0xd8, 0x8c, 0xea, 0x92, 0x7a, 0xc7, 0xf5, 0x39, 0xf1, 0xed, 0xf2, 0x28, 0x37, 0x6d, 0x25, });
  Check<SHA3<512>>("abc", { 0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a, 0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e, 0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d, 0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e, 0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9, 0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40, 0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5, 0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0, });

  Check<SHA3<224>>("", { 0x6b, 0x4e, 0x03, 0x42, 0x36, 0x67, 0xdb, 0xb7, 0x3b, 0x6e, 0x15, 0x45, 0x4f, 0x0e, 0xb1, 0xab, 0xd4, 0x59, 0x7f, 0x9a, 0x1b, 0x07, 0x8e, 0x3f, 0x5b, 0x5a, 0x6b, 0xc7, });
  Check<SHA3<256>>("", { 0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a, });
  Check<SHA3<384>>("", { 0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d, 0x01, 0x10, 0x7d, 0x85, 0x2e, 0x4c, 0x24, 0x85, 0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61, 0x99, 0x5e, 0x71, 0xbb, 0xee, 0x98, 0x3a, 0x2a, 0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47, 0xfb, 0x6b, 0xd1, 0xe0, 0x58, 0xd5, 0xf0, 0x04, });
  Check<SHA3<512>>("", { 0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e, 0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59, 0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6, 0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c, 0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58, 0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3, 0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26, });

  Check<SHA3<224>>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", { 0x8a, 0x24, 0x10, 0x8b, 0x15, 0x4a, 0xda, 0x21, 0xc9, 0xfd, 0x55, 0x74, 0x49, 0x44, 0x79, 0xba, 0x5c, 0x7e, 0x7a, 0xb7, 0x6e, 0xf2, 0x64, 0xea, 0xd0, 0xfc, 0xce, 0x33, });
  Check<SHA3<256>>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", { 0x41, 0xc0, 0xdb, 0xa2, 0xa9, 0xd6, 0x24, 0x08, 0x49, 0x10, 0x03, 0x76, 0xa8, 0x23, 0x5e, 0x2c, 0x82, 0xe1, 0xb9, 0x99, 0x8a, 0x99, 0x9e, 0x21, 0xdb, 0x32, 0xdd, 0x97, 0x49, 0x6d, 0x33, 0x76, });
  Check<SHA3<384>>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", { 0x99, 0x1c, 0x66, 0x57, 0x55, 0xeb, 0x3a, 0x4b, 0x6b, 0xbd, 0xfb, 0x75, 0xc7, 0x8a, 0x49, 0x2e, 0x8c, 0x56, 0xa2, 0x2c, 0x5c, 0x4d, 0x7e, 0x42, 0x9b, 0xfd, 0xbc, 0x32, 0xb9, 0xd4, 0xad, 0x5a, 0xa0, 0x4a, 0x1f, 0x07, 0x6e, 0x62, 0xfe, 0xa1, 0x9e, 0xef, 0x51, 0xac, 0xd0, 0x65, 0x7c, 0x22, });
  Check<SHA3<512>>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", { 0x04, 0xa3, 0x71, 0xe8, 0x4e, 0xcf, 0xb5, 0xb8, 0xb7, 0x7c, 0xb4, 0x86, 0x10, 0xfc, 0xa8, 0x18, 0x2d, 0xd4, 0x57, 0xce, 0x6f, 0x32, 0x6a, 0x0f, 0xd3, 0xd7, 0xec, 0x2f, 0x1e, 0x91, 0x63, 0x6d, 0xee, 0x69, 0x1f, 0xbe, 0x0c, 0x98, 0x53, 0x02, 0xba, 0x1b, 0x0d, 0x8d, 0xc7, 0x8c, 0x08, 0x63, 0x46, 0xb5, 0x33, 0xb4, 0x9c, 0x03, 0x0d, 0x99, 0xa2, 0x7d, 0xaf, 0x11, 0x39, 0xd6, 0xe7, 0x5e, });

  Check<SHA3<224>>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", { 0x54, 0x3e, 0x68, 0x68, 0xe1, 0x66, 0x6c, 0x1a, 0x64, 0x36, 0x30, 0xdf, 0x77, 0x36, 0x7a, 0xe5, 0xa6, 0x2a, 0x85, 0x07, 0x0a, 0x51, 0xc1, 0x4c, 0xbf, 0x66, 0x5c, 0xbc, });
  Check<SHA3<256>>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", { 0x91, 0x6f, 0x60, 0x61, 0xfe, 0x87, 0x97, 0x41, 0xca, 0x64, 0x69, 0xb4, 0x39, 0x71, 0xdf, 0xdb, 0x28, 0xb1, 0xa3, 0x2d, 0xc3, 0x6c, 0xb3, 0x25, 0x4e, 0x81, 0x2b, 0xe2, 0x7a, 0xad, 0x1d, 0x18, });
  Check<SHA3<384>>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", { 0x79, 0x40, 0x7d, 0x3b, 0x59, 0x16, 0xb5, 0x9c, 0x3e, 0x30, 0xb0, 0x98, 0x22, 0x97, 0x47, 0x91, 0xc3, 0x13, 0xfb, 0x9e, 0xcc, 0x84, 0x9e, 0x40, 0x6f, 0x23, 0x59, 0x2d, 0x04, 0xf6, 0x25, 0xdc, 0x8c, 0x70, 0x9b, 0x98, 0xb4, 0x3b, 0x38, 0x52, 0xb3, 0x37, 0x21, 0x61, 0x79, 0xaa, 0x7f, 0xc7, });
  Check<SHA3<512>>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", { 0xaf, 0xeb, 0xb2, 0xef, 0x54, 0x2e, 0x65, 0x79, 0xc5, 0x0c, 0xad, 0x06, 0xd2, 0xe5, 0x78, 0xf9, 0xf8, 0xdd, 0x68, 0x81, 0xd7, 0xdc, 0x82, 0x4d, 0x26, 0x36, 0x0f, 0xee, 0xbf, 0x18, 0xa4, 0xfa, 0x73, 0xe3, 0x26, 0x11, 0x22, 0x94, 0x8e, 0xfc, 0xfd, 0x49, 0x2e, 0x74, 0xe8, 0x2e, 0x21, 0x89, 0xed, 0x0f, 0xb4, 0x40, 0xd1, 0x87, 0xf3, 0x82, 0x27, 0x0c, 0xb4, 0x55, 0xf2, 0x1d, 0xd1, 0x85, });
}

}

