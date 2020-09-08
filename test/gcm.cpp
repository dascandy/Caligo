#include <catch/catch.hpp>
#include <caligo/gcm.h>
#include <caligo/aes.h>

template <size_t bits>
void test_aes(s2::vector<uint8_t> key, s2::vector<uint8_t> iv, s2::vector<uint8_t> plaintext, s2::vector<uint8_t> ciphertext, s2::vector<uint8_t> aad, s2::array<uint8_t, 16> tag) {
  auto [c_data, tag_data] = GCM<AES<bits>>({key, iv}).Encrypt(plaintext, aad);
  REQUIRE(c_data == ciphertext);
  REQUIRE(tag_data == tag);

  auto [p_data, is_valid] = GCM<AES<bits>>({key, iv}).Decrypt(ciphertext, aad, tag);
  REQUIRE(p_data == plaintext);
  REQUIRE(is_valid);
}

TEST_CASE("GCM test vectors", "[GCM]") {
  test_aes<128>({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {}, {}, {}, {0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a, }); 
  test_aes<128>({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78, }, {}, {0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf, }); 
  test_aes<128>({0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, }, {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, }, {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55, }, {0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85, }, {}, {0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64, 0xa6, 0x2c, 0xf3, 0x5a, 0xbd, 0x2b, 0xa6, 0xfa, 0xb4, }); 
  test_aes<128>({0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, }, {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, }, {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, }, {0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91, }, {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2, }, {0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47, }); 
  test_aes<256>({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {}, {}, {}, {0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b, }); 
  test_aes<256>({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18, }, {}, {0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19, }); 
  test_aes<256>({0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, }, {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, }, {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55, }, {0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad, }, {}, {0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd, 0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3, 0xcc, 0x6c, }); 
  test_aes<256>({0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, }, {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, }, {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, }, {0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62, }, {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2, }, {0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b, }); 
  test_aes<128>({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {}, {}, {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55, 0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad, }, {0x5f, 0xea, 0x79, 0x3a, 0x2d, 0x6f, 0x97, 0x4d, 0x37, 0xe6, 0x8e, 0x0c, 0xb8, 0xff, 0x94, 0x92, }); 
  test_aes<128>({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78, 0xf7, 0x95, 0xaa, 0xab, 0x49, 0x4b, 0x59, 0x23, 0xf7, 0xfd, 0x89, 0xff, 0x94, 0x8b, 0xc1, 0xe0, 0x20, 0x02, 0x11, 0x21, 0x4e, 0x73, 0x94, 0xda, 0x20, 0x89, 0xb6, 0xac, 0xd0, 0x93, 0xab, 0xe0, }, {}, {0x9d, 0xd0, 0xa3, 0x76, 0xb0, 0x8e, 0x40, 0xeb, 0x00, 0xc3, 0x5f, 0x29, 0xf9, 0xea, 0x61, 0xa4, }); 
  test_aes<128>({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78, 0xf7, 0x95, 0xaa, 0xab, 0x49, 0x4b, 0x59, 0x23, 0xf7, 0xfd, 0x89, 0xff, 0x94, 0x8b, 0xc1, 0xe0, 0x20, 0x02, 0x11, 0x21, 0x4e, 0x73, 0x94, 0xda, 0x20, 0x89, 0xb6, 0xac, 0xd0, 0x93, 0xab, 0xe0, 0xc9, 0x4d, 0xa2, 0x19, 0x11, 0x8e, 0x29, 0x7d, 0x7b, 0x7e, 0xbc, 0xbc, 0xc9, 0xc3, 0x88, 0xf2, 0x8a, 0xde, 0x7d, 0x85, 0xa8, 0xee, 0x35, 0x61, 0x6f, 0x71, 0x24, 0xa9, 0xd5, 0x27, 0x02, 0x91, }, {}, {0x98, 0x88, 0x5a, 0x3a, 0x22, 0xbd, 0x47, 0x42, 0xfe, 0x7b, 0x72, 0x17, 0x21, 0x93, 0xb1, 0x63, }); 
  test_aes<128>({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78, 0xf7, 0x95, 0xaa, 0xab, 0x49, 0x4b, 0x59, 0x23, 0xf7, 0xfd, 0x89, 0xff, 0x94, 0x8b, 0xc1, 0xe0, 0x20, 0x02, 0x11, 0x21, 0x4e, 0x73, 0x94, 0xda, 0x20, 0x89, 0xb6, 0xac, 0xd0, 0x93, 0xab, 0xe0, 0xc9, 0x4d, 0xa2, 0x19, 0x11, 0x8e, 0x29, 0x7d, 0x7b, 0x7e, 0xbc, 0xbc, 0xc9, 0xc3, 0x88, 0xf2, 0x8a, 0xde, 0x7d, 0x85, 0xa8, 0xee, 0x35, 0x61, 0x6f, 0x71, 0x24, 0xa9, 0xd5, 0x27, 0x02, 0x91, 0x95, 0xb8, 0x4d, 0x1b, 0x96, 0xc6, 0x90, 0xff, 0x2f, 0x2d, 0xe3, 0x0b, 0xf2, 0xec, 0x89, 0xe0, 0x02, 0x53, 0x78, 0x6e, 0x12, 0x65, 0x04, 0xf0, 0xda, 0xb9, 0x0c, 0x48, 0xa3, 0x03, 0x21, 0xde, 0x33, 0x45, 0xe6, 0xb0, 0x46, 0x1e, 0x7c, 0x9e, 0x6c, 0x6b, 0x7a, 0xfe, 0xdd, 0xe8, 0x3f, 0x40, }, {}, {0xca, 0xc4, 0x5f, 0x60, 0xe3, 0x1e, 0xfd, 0x3b, 0x5a, 0x43, 0xb9, 0x8a, 0x22, 0xce, 0x1a, 0xa1, }); 
  test_aes<128>({0x84, 0x3f, 0xfc, 0xf5, 0xd2, 0xb7, 0x26, 0x94, 0xd1, 0x9e, 0xd0, 0x1d, 0x01, 0x24, 0x94, 0x12, }, {0xdb, 0xcc, 0xa3, 0x2e, 0xbf, 0x9b, 0x80, 0x46, 0x17, 0xc3, 0xaa, 0x9e, }, {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, }, {0x62, 0x68, 0xc6, 0xfa, 0x2a, 0x80, 0xb2, 0xd1, 0x37, 0x46, 0x7f, 0x09, 0x2f, 0x65, 0x7a, 0xc0, 0x4d, 0x89, 0xbe, 0x2b, 0xea, 0xa6, 0x23, 0xd6, 0x1b, 0x5a, 0x86, 0x8c, 0x8f, 0x03, 0xff, 0x95, 0xd3, 0xdc, 0xee, 0x23, 0xad, 0x2f, 0x1a, 0xb3, 0xa6, 0xc8, 0x0e, 0xaf, 0x4b, 0x14, 0x0e, 0xb0, 0x5d, 0xe3, 0x45, 0x7f, 0x0f, 0xbc, 0x11, 0x1a, 0x6b, 0x43, 0xd0, 0x76, 0x3a, 0xa4, 0x22, 0xa3, 0x01, 0x3c, 0xf1, 0xdc, 0x37, 0xfe, 0x41, 0x7d, 0x1f, 0xbf, 0xc4, 0x49, 0xb7, 0x5d, 0x4c, 0xc5, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, }, {0x3b, 0x62, 0x9c, 0xcf, 0xbc, 0x11, 0x19, 0xb7, 0x31, 0x9e, 0x1d, 0xce, 0x2c, 0xd6, 0xfd, 0x6d, }); 
}

// Test cases with non-12 byte IV
//  test_aes<128>({0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, }, {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, }, {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, }, {0x61, 0x35, 0x3b, 0x4c, 0x28, 0x06, 0x93, 0x4a, 0x77, 0x7f, 0xf5, 0x1f, 0xa2, 0x2a, 0x47, 0x55, 0x69, 0x9b, 0x2a, 0x71, 0x4f, 0xcd, 0xc6, 0xf8, 0x37, 0x66, 0xe5, 0xf9, 0x7b, 0x6c, 0x74, 0x23, 0x73, 0x80, 0x69, 0x00, 0xe4, 0x9f, 0x24, 0xb2, 0x2b, 0x09, 0x75, 0x44, 0xd4, 0x89, 0x6b, 0x42, 0x49, 0x89, 0xb5, 0xe1, 0xeb, 0xac, 0x0f, 0x07, 0xc2, 0x3f, 0x45, 0x98, }, {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2, }, {0x36, 0x12, 0xd2, 0xe7, 0x9e, 0x3b, 0x07, 0x85, 0x56, 0x1b, 0xe1, 0x4a, 0xac, 0xa2, 0xfc, 0xcb, }); 
//  test_aes<128>({0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, }, {0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5, 0x55, 0x90, 0x9c, 0x5a, 0xff, 0x52, 0x69, 0xaa, 0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d, 0xa1, 0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28, 0xc3, 0xc0, 0xc9, 0x51, 0x56, 0x80, 0x95, 0x39, 0xfc, 0xf0, 0xe2, 0x42, 0x9a, 0x6b, 0x52, 0x54, 0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57, 0xa6, 0x37, 0xb3, 0x9b, }, {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, }, {0x8c, 0xe2, 0x49, 0x98, 0x62, 0x56, 0x15, 0xb6, 0x03, 0xa0, 0x33, 0xac, 0xa1, 0x3f, 0xb8, 0x94, 0xbe, 0x91, 0x12, 0xa5, 0xc3, 0xa2, 0x11, 0xa8, 0xba, 0x26, 0x2a, 0x3c, 0xca, 0x7e, 0x2c, 0xa7, 0x01, 0xe4, 0xa9, 0xa4, 0xfb, 0xa4, 0x3c, 0x90, 0xcc, 0xdc, 0xb2, 0x81, 0xd4, 0x8c, 0x7c, 0x6f, 0xd6, 0x28, 0x75, 0xd2, 0xac, 0xa4, 0x17, 0x03, 0x4c, 0x34, 0xae, 0xe5, }, {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2, }, {0x61, 0x9c, 0xc5, 0xae, 0xff, 0xfe, 0x0b, 0xfa, 0x46, 0x2a, 0xf4, 0x3c, 0x16, 0x99, 0xd0, 0x50, }); 
//  test_aes<256>({0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, }, {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, }, {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, }, {0xc3, 0x76, 0x2d, 0xf1, 0xca, 0x78, 0x7d, 0x32, 0xae, 0x47, 0xc1, 0x3b, 0xf1, 0x98, 0x44, 0xcb, 0xaf, 0x1a, 0xe1, 0x4d, 0x0b, 0x97, 0x6a, 0xfa, 0xc5, 0x2f, 0xf7, 0xd7, 0x9b, 0xba, 0x9d, 0xe0, 0xfe, 0xb5, 0x82, 0xd3, 0x39, 0x34, 0xa4, 0xf0, 0x95, 0x4c, 0xc2, 0x36, 0x3b, 0xc7, 0x3f, 0x78, 0x62, 0xac, 0x43, 0x0e, 0x64, 0xab, 0xe4, 0x99, 0xf4, 0x7c, 0x9b, 0x1f, }, {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2, }, {0x3a, 0x33, 0x7d, 0xbf, 0x46, 0xa7, 0x92, 0xc4, 0x5e, 0x45, 0x49, 0x13, 0xfe, 0x2e, 0xa8, 0xf2, }); 
//  test_aes<256>({0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, }, {0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5, 0x55, 0x90, 0x9c, 0x5a, 0xff, 0x52, 0x69, 0xaa, 0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d, 0xa1, 0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28, 0xc3, 0xc0, 0xc9, 0x51, 0x56, 0x80, 0x95, 0x39, 0xfc, 0xf0, 0xe2, 0x42, 0x9a, 0x6b, 0x52, 0x54, 0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57, 0xa6, 0x37, 0xb3, 0x9b, }, {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, }, {0x5a, 0x8d, 0xef, 0x2f, 0x0c, 0x9e, 0x53, 0xf1, 0xf7, 0x5d, 0x78, 0x53, 0x65, 0x9e, 0x2a, 0x20, 0xee, 0xb2, 0xb2, 0x2a, 0xaf, 0xde, 0x64, 0x19, 0xa0, 0x58, 0xab, 0x4f, 0x6f, 0x74, 0x6b, 0xf4, 0x0f, 0xc0, 0xc3, 0xb7, 0x80, 0xf2, 0x44, 0x45, 0x2d, 0xa3, 0xeb, 0xf1, 0xc5, 0xd8, 0x2c, 0xde, 0xa2, 0x41, 0x89, 0x97, 0x20, 0x0e, 0xf8, 0x2e, 0x44, 0xae, 0x7e, 0x3f, }, {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2, }, {0xa4, 0x4a, 0x82, 0x66, 0xee, 0x1c, 0x8e, 0xb0, 0xc8, 0xb5, 0xd4, 0xcf, 0x5a, 0xe9, 0xf1, 0x9a, }); 
//  test_aes<128>({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }, {0x56, 0xb3, 0x37, 0x3c, 0xa9, 0xef, 0x6e, 0x4a, 0x2b, 0x64, 0xfe, 0x1e, 0x9a, 0x17, 0xb6, 0x14, 0x25, 0xf1, 0x0d, 0x47, 0xa7, 0x5a, 0x5f, 0xce, 0x13, 0xef, 0xc6, 0xbc, 0x78, 0x4a, 0xf2, 0x4f, 0x41, 0x41, 0xbd, 0xd4, 0x8c, 0xf7, 0xc7, 0x70, 0x88, 0x7a, 0xfd, 0x57, 0x3c, 0xca, 0x54, 0x18, 0xa9, 0xae, 0xff, 0xcd, 0x7c, 0x5c, 0xed, 0xdf, 0xc6, 0xa7, 0x83, 0x97, 0xb9, 0xa8, 0x5b, 0x49, 0x9d, 0xa5, 0x58, 0x25, 0x72, 0x67, 0xca, 0xab, 0x2a, 0xd0, 0xb2, 0x3c, 0xa4, 0x76, 0xa5, 0x3c, 0xb1, 0x7f, 0xb4, 0x1c, 0x4b, 0x8b, 0x47, 0x5c, 0xb4, 0xf3, 0xf7, 0x16, 0x50, 0x94, 0xc2, 0x29, 0xc9, 0xe8, 0xc4, 0xdc, 0x0a, 0x2a, 0x5f, 0xf1, 0x90, 0x3e, 0x50, 0x15, 0x11, 0x22, 0x13, 0x76, 0xa1, 0xcd, 0xb8, 0x36, 0x4c, 0x50, 0x61, 0xa2, 0x0c, 0xae, 0x74, 0xbc, 0x4a, 0xcd, 0x76, 0xce, 0xb0, 0xab, 0xc9, 0xfd, 0x32, 0x17, 0xef, 0x9f, 0x8c, 0x90, 0xbe, 0x40, 0x2d, 0xdf, 0x6d, 0x86, 0x97, 0xf4, 0xf8, 0x80, 0xdf, 0xf1, 0x5b, 0xfb, 0x7a, 0x6b, 0x28, 0x24, 0x1e, 0xc8, 0xfe, 0x18, 0x3c, 0x2d, 0x59, 0xe3, 0xf9, 0xdf, 0xff, 0x65, 0x3c, 0x71, 0x26, 0xf0, 0xac, 0xb9, 0xe6, 0x42, 0x11, 0xf4, 0x2b, 0xae, 0x12, 0xaf, 0x46, 0x2b, 0x10, 0x70, 0xbe, 0xf1, 0xab, 0x5e, 0x36, 0x06, }, {}, {0x56, 0x6f, 0x8e, 0xf6, 0x83, 0x07, 0x8b, 0xfd, 0xee, 0xff, 0xa8, 0x69, 0xd7, 0x51, 0xa0, 0x17, }); 



