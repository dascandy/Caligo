#include <caligo/rsa.h>
#include <caligo/sha1.h>
#include <caligo/sha2.h>
#include <catch2/catch.hpp>

namespace Caligo {

template <size_t Bits, typename Hash>
void test_pss(std::span<const uint8_t> n, 
              std::span<const uint8_t> e,
              std::span<const uint8_t> d,
              std::span<const uint8_t> salt,
              std::span<const uint8_t> msg,
              std::span<const uint8_t> s) {
  std::vector<uint8_t> nn(n.data(), n.data() + n.size());
  std::vector<uint8_t> ee(e.data(), e.data() + e.size());
  std::vector<uint8_t> dd(d.data(), d.data() + d.size());
  std::reverse(nn.begin(), nn.end());
  std::reverse(ee.begin(), ee.end());
  std::reverse(dd.begin(), dd.end());

  rsa_public_key<Bits> pubkey = rsa_public_key<Bits>(bignum<Bits>(nn), bignum<Bits>(ee));
  bool isOk = pubkey.template validatePssSignature<Hash, Caligo::MGF1<SHA1>>(msg, s);
  CHECK(isOk);

  rsa_private_key<Bits> privkey = rsa_private_key<Bits>(bignum<Bits>(nn), bignum<Bits>(dd));
  std::array<uint8_t, Hash::hashsize> msghash = Hash(msg);
  std::vector<uint8_t> salt2(salt.begin(), salt.end());
  salt2[0] ^= 1;
  std::vector<uint8_t> newSig = privkey.template signPssSignature<Hash, Caligo::MGF1<SHA1>>(msghash, salt2);
  CHECK(newSig != std::vector<uint8_t>(s.begin(), s.end()));
  
  salt2[0] ^= 2;
  std::vector<uint8_t> thirdSig = privkey.template signPssSignature<Hash, Caligo::MGF1<SHA1>>(msghash, salt2);
  CHECK(newSig != thirdSig);

  bool alsoOk = pubkey.template validatePssSignature<Hash, Caligo::MGF1<SHA1>>(msg, newSig) &&
                pubkey.template validatePssSignature<Hash, Caligo::MGF1<SHA1>>(msg, thirdSig);
  CHECK(alsoOk);
}

TEST_CASE("RSA PSS signature", "[RSA]") {
  SECTION("RSA 1024") {
    std::vector<uint8_t> n = { 0xbc, 0xb4, 0x7b, 0x2e, 0x0d, 0xaf, 0xcb, 0xa8, 0x1f, 0xf2, 0xa2, 0xb5, 0xcb, 0x11, 0x5c, 0xa7, 0xe7, 0x57, 0x18, 0x4c, 0x9d, 0x72, 0xbc, 0xdc, 0xda, 0x70, 0x7a, 0x14, 0x6b, 0x3b, 0x4e, 0x29, 0x98, 0x9d, 0xdc, 0x66, 0x0b, 0xd6, 0x94, 0x86, 0x5b, 0x93, 0x2b, 0x71, 0xca, 0x24, 0xa3, 0x35, 0xcf, 0x4d, 0x33, 0x9c, 0x71, 0x91, 0x83, 0xe6, 0x22, 0x2e, 0x4c, 0x9e, 0xa6, 0x87, 0x5a, 0xcd, 0x52, 0x8a, 0x49, 0xba, 0x21, 0x86, 0x3f, 0xe0, 0x81, 0x47, 0xc3, 0xa4, 0x7e, 0x41, 0x99, 0x0b, 0x51, 0xa0, 0x3f, 0x77, 0xd2, 0x21, 0x37, 0xf8, 0xd7, 0x4c, 0x43, 0xa5, 0xa4, 0x5f, 0x4e, 0x9e, 0x18, 0xa2, 0xd1, 0x5d, 0xb0, 0x51, 0xdc, 0x89, 0x38, 0x5d, 0xb9, 0xcf, 0x83, 0x74, 0xb6, 0x3a, 0x8c, 0xc8, 0x81, 0x13, 0x71, 0x0e, 0x6d, 0x81, 0x79, 0x07, 0x5b, 0x7d, 0xc7, 0x9e, 0xe7, 0x6b };
    std::vector<uint8_t> e = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01 };
    std::vector<uint8_t> d = { 0x38, 0x3a, 0x6f, 0x19, 0xe1, 0xea, 0x27, 0xfd, 0x08, 0xc7, 0xfb, 0xc3, 0xbf, 0xa6, 0x84, 0xbd, 0x63, 0x29, 0x88, 0x8c, 0x0b, 0xbe, 0x4c, 0x98, 0x62, 0x5e, 0x71, 0x81, 0xf4, 0x11, 0xcf, 0xd0, 0x85, 0x31, 0x44, 0xa3, 0x03, 0x94, 0x04, 0xdd, 0xa4, 0x1b, 0xce, 0x2e, 0x31, 0xd5, 0x88, 0xec, 0x57, 0xc0, 0xe1, 0x48, 0x14, 0x6f, 0x0f, 0xa6, 0x5b, 0x39, 0x00, 0x8b, 0xa5, 0x83, 0x5f, 0x82, 0x9b, 0xa3, 0x5a, 0xe2, 0xf1, 0x55, 0xd6, 0x1b, 0x8a, 0x12, 0x58, 0x1b, 0x99, 0xc9, 0x27, 0xfd, 0x2f, 0x22, 0x25, 0x2c, 0x5e, 0x73, 0xcb, 0xa4, 0xa6, 0x10, 0xdb, 0x39, 0x73, 0xe0, 0x19, 0xee, 0x0f, 0x95, 0x13, 0x0d, 0x43, 0x19, 0xed, 0x41, 0x34, 0x32, 0xf2, 0xe5, 0xe2, 0x0d, 0x52, 0x15, 0xcd, 0xd2, 0x7c, 0x21, 0x64, 0x20, 0x6b, 0x3f, 0x80, 0xed, 0xee, 0x51, 0x93, 0x8a, 0x25, 0xc1 };
    SECTION("SHA256") { 
      std::vector<uint8_t> salt = { 0x6f, 0x28, 0x41, 0x16, 0x6a, 0x64, 0x47, 0x1d, 0x4f, 0x0b, 0x8e, 0xd0, 0xdb, 0xb7, 0xdb, 0x32, 0x16, 0x1d, 0xa1, 0x3b };
      std::vector<uint8_t> msg = { 0x12, 0x48, 0xf6, 0x2a, 0x43, 0x89, 0xf4, 0x2f, 0x7b, 0x4b, 0xb1, 0x31, 0x05, 0x3d, 0x6c, 0x88, 0xa9, 0x94, 0xdb, 0x20, 0x75, 0xb9, 0x12, 0xcc, 0xbe, 0x3e, 0xa7, 0xdc, 0x61, 0x17, 0x14, 0xf1, 0x4e, 0x07, 0x5c, 0x10, 0x48, 0x58, 0xf2, 0xf6, 0xe6, 0xcf, 0xd6, 0xab, 0xde, 0xdf, 0x01, 0x5a, 0x82, 0x1d, 0x03, 0x60, 0x8b, 0xf4, 0xeb, 0xa3, 0x16, 0x9a, 0x67, 0x25, 0xec, 0x42, 0x2c, 0xd9, 0x06, 0x94, 0x98, 0xb5, 0x51, 0x5a, 0x96, 0x08, 0xae, 0x7c, 0xc3, 0x0e, 0x3d, 0x2e, 0xcf, 0xc1, 0xdb, 0x68, 0x25, 0xf3, 0xe9, 0x96, 0xce, 0x9a, 0x50, 0x92, 0x92, 0x6b, 0xc1, 0xcf, 0x61, 0xaa, 0x42, 0xd7, 0xf2, 0x40, 0xe6, 0xf7, 0xaa, 0x0e, 0xdb, 0x38, 0xbf, 0x81, 0xaa, 0x92, 0x9d, 0x66, 0xbb, 0x5d, 0x89, 0x00, 0x18, 0x08, 0x84, 0x58, 0x72, 0x0d, 0x72, 0xd5, 0x69, 0x24, 0x7b, 0x0c };
      std::vector<uint8_t> s = { 0x7b, 0x1d, 0x37, 0x27, 0x8e, 0x54, 0x98, 0x98, 0xd4, 0x08, 0x4e, 0x22, 0x10, 0xc4, 0xa9, 0x96, 0x1e, 0xdf, 0xe7, 0xb5, 0x96, 0x35, 0x50, 0xcc, 0xa1, 0x90, 0x42, 0x48, 0xc8, 0x68, 0x15, 0x13, 0x53, 0x90, 0x17, 0x82, 0x0f, 0x0e, 0x9b, 0xd0, 0x74, 0xb9, 0xf8, 0xa0, 0x67, 0xb9, 0xfe, 0xff, 0xf7, 0xf1, 0xfa, 0x20, 0xbf, 0x2d, 0x0c, 0x75, 0x01, 0x5f, 0xf0, 0x20, 0xb2, 0x21, 0x0c, 0xc7, 0xf7, 0x90, 0x34, 0xfe, 0xdf, 0x68, 0xe8, 0xd4, 0x4a, 0x00, 0x7a, 0xbf, 0x4d, 0xd8, 0x2c, 0x26, 0xe8, 0xb0, 0x03, 0x93, 0x72, 0x3a, 0xea, 0x15, 0xab, 0xfb, 0xc2, 0x29, 0x41, 0xc8, 0xcf, 0x79, 0x48, 0x17, 0x18, 0xc0, 0x08, 0xda, 0x71, 0x3f, 0xb8, 0xf5, 0x4c, 0xb3, 0xfc, 0xa8, 0x90, 0xbd, 0xe1, 0x13, 0x73, 0x14, 0x33, 0x4b, 0x9b, 0x0a, 0x18, 0x51, 0x5b, 0xfa, 0x48, 0xe5, 0xcc, 0xd0 };
      test_pss<1024, SHA2<256>>(n, e, d, salt, msg, s);
    }

    SECTION("SHA384") {
      std::vector<uint8_t> salt = { 0x6f, 0x28, 0x41, 0x16, 0x6a, 0x64, 0x47, 0x1d, 0x4f, 0x0b, 0x8e, 0xd0, 0xdb, 0xb7, 0xdb, 0x32, 0x16, 0x1d, 0xa1, 0x3b };
      std::vector<uint8_t> msg = { 0x12, 0x48, 0xf6, 0x2a, 0x43, 0x89, 0xf4, 0x2f, 0x7b, 0x4b, 0xb1, 0x31, 0x05, 0x3d, 0x6c, 0x88, 0xa9, 0x94, 0xdb, 0x20, 0x75, 0xb9, 0x12, 0xcc, 0xbe, 0x3e, 0xa7, 0xdc, 0x61, 0x17, 0x14, 0xf1, 0x4e, 0x07, 0x5c, 0x10, 0x48, 0x58, 0xf2, 0xf6, 0xe6, 0xcf, 0xd6, 0xab, 0xde, 0xdf, 0x01, 0x5a, 0x82, 0x1d, 0x03, 0x60, 0x8b, 0xf4, 0xeb, 0xa3, 0x16, 0x9a, 0x67, 0x25, 0xec, 0x42, 0x2c, 0xd9, 0x06, 0x94, 0x98, 0xb5, 0x51, 0x5a, 0x96, 0x08, 0xae, 0x7c, 0xc3, 0x0e, 0x3d, 0x2e, 0xcf, 0xc1, 0xdb, 0x68, 0x25, 0xf3, 0xe9, 0x96, 0xce, 0x9a, 0x50, 0x92, 0x92, 0x6b, 0xc1, 0xcf, 0x61, 0xaa, 0x42, 0xd7, 0xf2, 0x40, 0xe6, 0xf7, 0xaa, 0x0e, 0xdb, 0x38, 0xbf, 0x81, 0xaa, 0x92, 0x9d, 0x66, 0xbb, 0x5d, 0x89, 0x00, 0x18, 0x08, 0x84, 0x58, 0x72, 0x0d, 0x72, 0xd5, 0x69, 0x24, 0x7b, 0x0c };
      std::vector<uint8_t> s = { 0x8f, 0x16, 0xc8, 0x07, 0xbe, 0xf3, 0xed, 0x6f, 0x74, 0xee, 0x7f, 0xf5, 0xc3, 0x60, 0xa5, 0x42, 0x8c, 0x6c, 0x2f, 0x10, 0x51, 0x78, 0xb5, 0x8f, 0xf7, 0xd0, 0x73, 0xe5, 0x66, 0xda, 0xd6, 0xe7, 0x71, 0x8d, 0x31, 0x29, 0xc7, 0x68, 0xcd, 0x5a, 0x96, 0x66, 0xde, 0x2b, 0x6c, 0x94, 0x71, 0x77, 0xb4, 0x57, 0x09, 0xdc, 0x7c, 0xd0, 0xf4, 0x3b, 0x0b, 0xa6, 0xfc, 0x75, 0x57, 0x8e, 0x11, 0x96, 0xac, 0xc1, 0x5c, 0xa3, 0xaf, 0xe4, 0xa7, 0x8c, 0x14, 0x4c, 0xb6, 0x88, 0x5c, 0x1c, 0xc8, 0x15, 0xf7, 0xf9, 0x89, 0x25, 0xbc, 0x04, 0xad, 0x2f, 0xf2, 0x0f, 0xc1, 0x06, 0x8b, 0x04, 0x5d, 0x94, 0x50, 0xe2, 0xa1, 0xdc, 0xf5, 0xa1, 0x61, 0xce, 0xab, 0xba, 0x2b, 0x0b, 0x66, 0xc7, 0x35, 0x4f, 0xdb, 0x80, 0xfa, 0x1d, 0x72, 0x9e, 0x5f, 0x97, 0x63, 0x87, 0xf2, 0x4a, 0x69, 0x7a, 0x7e, 0x56 };
      test_pss<1024, SHA2<384>>(n, e, d, salt, msg, s);
    }

    SECTION("SHA512") {
      std::vector<uint8_t> salt = { 0x6f, 0x28, 0x41, 0x16, 0x6a, 0x64, 0x47, 0x1d, 0x4f, 0x0b, 0x8e, 0xd0, 0xdb, 0xb7, 0xdb, 0x32, 0x16, 0x1d, 0xa1, 0x3b };
      std::vector<uint8_t> msg = { 0x12, 0x48, 0xf6, 0x2a, 0x43, 0x89, 0xf4, 0x2f, 0x7b, 0x4b, 0xb1, 0x31, 0x05, 0x3d, 0x6c, 0x88, 0xa9, 0x94, 0xdb, 0x20, 0x75, 0xb9, 0x12, 0xcc, 0xbe, 0x3e, 0xa7, 0xdc, 0x61, 0x17, 0x14, 0xf1, 0x4e, 0x07, 0x5c, 0x10, 0x48, 0x58, 0xf2, 0xf6, 0xe6, 0xcf, 0xd6, 0xab, 0xde, 0xdf, 0x01, 0x5a, 0x82, 0x1d, 0x03, 0x60, 0x8b, 0xf4, 0xeb, 0xa3, 0x16, 0x9a, 0x67, 0x25, 0xec, 0x42, 0x2c, 0xd9, 0x06, 0x94, 0x98, 0xb5, 0x51, 0x5a, 0x96, 0x08, 0xae, 0x7c, 0xc3, 0x0e, 0x3d, 0x2e, 0xcf, 0xc1, 0xdb, 0x68, 0x25, 0xf3, 0xe9, 0x96, 0xce, 0x9a, 0x50, 0x92, 0x92, 0x6b, 0xc1, 0xcf, 0x61, 0xaa, 0x42, 0xd7, 0xf2, 0x40, 0xe6, 0xf7, 0xaa, 0x0e, 0xdb, 0x38, 0xbf, 0x81, 0xaa, 0x92, 0x9d, 0x66, 0xbb, 0x5d, 0x89, 0x00, 0x18, 0x08, 0x84, 0x58, 0x72, 0x0d, 0x72, 0xd5, 0x69, 0x24, 0x7b, 0x0c };
      std::vector<uint8_t> s = { 0xa8, 0x33, 0xba, 0x31, 0x63, 0x4f, 0x87, 0x73, 0xe4, 0xfe, 0x6e, 0xa0, 0xc6, 0x9e, 0x1a, 0x23, 0x76, 0x6a, 0x93, 0x9d, 0x34, 0xb3, 0x2f, 0xc7, 0x8b, 0x77, 0x4b, 0x22, 0xe4, 0x6a, 0x64, 0x6c, 0x25, 0xe6, 0xe1, 0x06, 0x2d, 0x23, 0x4e, 0xd4, 0x8b, 0x1a, 0xba, 0x0f, 0x83, 0x05, 0x29, 0xff, 0x6a, 0xfc, 0x29, 0x6c, 0xc8, 0xdc, 0x20, 0x7b, 0xbc, 0x15, 0x39, 0x16, 0x23, 0xbe, 0xac, 0x5f, 0x6c, 0x3d, 0xb5, 0x57, 0xca, 0x49, 0xd0, 0xe4, 0x2c, 0x96, 0x2d, 0xe9, 0x5b, 0x5f, 0xf5, 0x48, 0xcf, 0xf9, 0x70, 0xf5, 0xc7, 0x3f, 0x43, 0x9c, 0xfe, 0x82, 0xd3, 0x90, 0x7b, 0xe6, 0x02, 0x40, 0xf5, 0x6b, 0x6a, 0x42, 0x59, 0xcc, 0x96, 0xdf, 0xd8, 0xfe, 0x02, 0xa0, 0xbf, 0xa2, 0x6e, 0x02, 0x23, 0xf6, 0x82, 0x14, 0x42, 0x8f, 0xff, 0x0a, 0xe4, 0x01, 0x62, 0x19, 0x8c, 0xc5, 0xcb, 0xd1 };
      test_pss<1024, SHA2<512>>(n, e, d, salt, msg, s);
    }
  }
  SECTION("RSA 2048") {
    std::vector<uint8_t> n = { 0xd9, 0x5b, 0x71, 0xc9, 0xdf, 0xee, 0x45, 0x3b, 0xa1, 0xb1, 0xa7, 0xde, 0x2c, 0x1f, 0x0b, 0x0a, 0x67, 0x57, 0x9e, 0xe9, 0x1d, 0x1d, 0x3a, 0xd9, 0x7e, 0x48, 0x18, 0x29, 0xb8, 0x6e, 0xda, 0xc7, 0x50, 0xc4, 0x8e, 0x12, 0xa8, 0xcd, 0xb0, 0x26, 0xc8, 0x2f, 0x27, 0x3d, 0xaf, 0xc2, 0x22, 0x00, 0x9f, 0x0d, 0xb3, 0xb0, 0x8b, 0x2d, 0xb1, 0x0a, 0x69, 0xc4, 0xb2, 0xdd, 0xda, 0xae, 0xce, 0xac, 0x1b, 0x0c, 0x86, 0x26, 0x82, 0xee, 0xf2, 0x94, 0xe5, 0x79, 0xf5, 0x5a, 0xab, 0x87, 0x1b, 0xc0, 0xa7, 0xee, 0xab, 0xc9, 0x23, 0xc9, 0xe8, 0x0d, 0xdd, 0xc2, 0x2e, 0xc0, 0xa2, 0x70, 0x02, 0xae, 0xe6, 0xa5, 0xba, 0x66, 0x39, 0x7f, 0x41, 0x2b, 0xba, 0xf5, 0xfb, 0x4e, 0xaf, 0x66, 0xa1, 0xa0, 0xf8, 0x2e, 0xaf, 0x68, 0x27, 0x19, 0x8c, 0xaf, 0x49, 0xb3, 0x47, 0x25, 0x8b, 0x12, 0x83, 0xe8, 0xcb, 0xb1, 0x0d, 0xa2, 0x83, 0x7f, 0x6e, 0xcc, 0x34, 0x90, 0xc7, 0x28, 0xfe, 0x92, 0x7f, 0x44, 0x45, 0x5a, 0x6f, 0x19, 0x4f, 0x37, 0x76, 0xbf, 0x79, 0x15, 0x1d, 0x9a, 0xd7, 0xe2, 0xda, 0xf7, 0x70, 0xb3, 0x7d, 0x12, 0x62, 0x7c, 0xc0, 0xc5, 0xfb, 0x62, 0x48, 0x4f, 0x46, 0x25, 0x8d, 0x9c, 0xe2, 0xc1, 0x1b, 0x26, 0x25, 0x6d, 0x09, 0xcb, 0x41, 0x2f, 0x8d, 0x8f, 0x8f, 0x1f, 0xe9, 0x1b, 0xb9, 0x4a, 0xc2, 0x7d, 0xe6, 0xd2, 0x6a, 0x83, 0xa8, 0x43, 0x9e, 0x51, 0xb3, 0x5d, 0xbe, 0xe4, 0x6b, 0x3b, 0x8f, 0xf9, 0x91, 0xd6, 0x67, 0xbb, 0x53, 0xee, 0xee, 0x85, 0xff, 0x16, 0x52, 0xc8, 0x98, 0x1f, 0x14, 0x1d, 0x47, 0xc8, 0x20, 0x57, 0x91, 0xce, 0xf5, 0xb3, 0x2d, 0x71, 0x8d, 0xdc, 0x08, 0x2e, 0xd0, 0xdd, 0x54, 0x28, 0x26, 0x41, 0x6b, 0x22, 0x71, 0x06, 0x4e, 0xf4, 0x37, 0xa9 };
    std::vector<uint8_t> e = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01 };
    std::vector<uint8_t> d = { 0x2f, 0x21, 0xb0, 0x1b, 0xe9, 0x4d, 0xde, 0x7f, 0x5e, 0xc1, 0x8a, 0x38, 0x17, 0xf3, 0x27, 0x4e, 0xbb, 0x37, 0xf9, 0xc2, 0x6c, 0xc8, 0xc0, 0xd1, 0x16, 0x9c, 0x05, 0x79, 0x4e, 0x7f, 0xe3, 0x3a, 0xe3, 0x1d, 0xab, 0xfd, 0x09, 0xd3, 0x88, 0x45, 0xf0, 0x94, 0xa0, 0xfa, 0xb4, 0x58, 0xf1, 0x4c, 0x97, 0x30, 0xbe, 0x6d, 0x22, 0xd0, 0xe6, 0x99, 0xee, 0x73, 0x73, 0xa1, 0xbd, 0xe0, 0xb7, 0xfa, 0x03, 0xe7, 0x84, 0x53, 0x67, 0x82, 0xee, 0xe1, 0x30, 0x9d, 0x70, 0x81, 0x97, 0xbe, 0x35, 0x5b, 0x62, 0x4e, 0xd3, 0xbb, 0x4a, 0xe2, 0x66, 0x4a, 0x53, 0x72, 0xde, 0xf6, 0x70, 0x82, 0xbf, 0x62, 0x33, 0xab, 0x6e, 0x2e, 0xea, 0x7a, 0xd8, 0xa3, 0xe5, 0xe7, 0x9e, 0xf5, 0xe1, 0xfc, 0xec, 0x41, 0x5e, 0x6f, 0xa9, 0x23, 0x79, 0x8f, 0x05, 0xbd, 0xa0, 0xca, 0x9a, 0x3b, 0xde, 0xdb, 0x45, 0xf4, 0xd7, 0x81, 0xef, 0x1a, 0x4f, 0x50, 0x75, 0xcd, 0x9b, 0xb3, 0x99, 0x63, 0x5d, 0xa3, 0xe9, 0xa6, 0x88, 0x0e, 0xd0, 0x21, 0xa7, 0x50, 0xbc, 0x98, 0x06, 0xaf, 0x81, 0xfb, 0xff, 0xcd, 0x4a, 0xce, 0xaf, 0x80, 0x4e, 0xc7, 0x68, 0x08, 0xae, 0x18, 0x67, 0x15, 0xc7, 0x72, 0xca, 0xa9, 0x61, 0xa8, 0x62, 0x99, 0x1c, 0x67, 0xca, 0x8b, 0xff, 0xef, 0x6b, 0x34, 0x08, 0x7b, 0x44, 0xdb, 0x5b, 0x59, 0xab, 0xce, 0x09, 0x31, 0x77, 0x47, 0xfc, 0x75, 0x25, 0x2f, 0x17, 0x05, 0x26, 0x0b, 0x13, 0xdd, 0x62, 0xcc, 0xbc, 0x74, 0x50, 0x91, 0xf3, 0xc1, 0xb6, 0x4f, 0x59, 0x03, 0x1d, 0x34, 0x0c, 0x73, 0x62, 0xa0, 0xe1, 0x06, 0x6a, 0xb0, 0x55, 0x4d, 0x46, 0x6f, 0x20, 0x9a, 0x3c, 0xf5, 0x1b, 0xc6, 0x4b, 0x3c, 0x70, 0xc3, 0xce, 0x52, 0xf4, 0x13, 0xd8, 0x1b, 0x22, 0x8f, 0xa3, 0x1d, 0x9e, 0xfd };

    SECTION("SHA256") {
      std::vector<uint8_t> salt = { 0x6f, 0x28, 0x41, 0x16, 0x6a, 0x64, 0x47, 0x1d, 0x4f, 0x0b, 0x8e, 0xd0, 0xdb, 0xb7, 0xdb, 0x32, 0x16, 0x1d, 0xa1, 0x3b };
      std::vector<uint8_t> msg = { 0xcd, 0x74, 0xae, 0x61, 0x52, 0xd5, 0xfe, 0x5c, 0xe3, 0xd9, 0x07, 0x3c, 0x92, 0x1e, 0x86, 0x1a, 0x24, 0x20, 0x8f, 0x0c, 0x68, 0x47, 0x7f, 0x49, 0xc8, 0x25, 0x33, 0x8e, 0x1e, 0xf8, 0x77, 0xc0, 0xc9, 0x77, 0xc1, 0xd2, 0xff, 0xcb, 0x20, 0xe9, 0x64, 0xdb, 0x6f, 0xbe, 0xdc, 0xcc, 0xce, 0x44, 0x9e, 0xc8, 0x53, 0x8c, 0x8b, 0xff, 0xfc, 0xe5, 0xbd, 0xec, 0xe8, 0x47, 0x62, 0xda, 0xc7, 0xf2, 0xcb, 0xa6, 0x90, 0x52, 0xc0, 0xc6, 0x72, 0x26, 0x17, 0x8a, 0x0c, 0xe1, 0x85, 0xa2, 0xe0, 0x50, 0xb3, 0xe1, 0x05, 0x7e, 0x94, 0x41, 0x1d, 0xd5, 0xf7, 0x26, 0x87, 0x85, 0x58, 0xe7, 0xd6, 0x2a, 0xfc, 0x8a, 0x81, 0xa9, 0x3d, 0xcf, 0xdb, 0x5a, 0x22, 0x71, 0x46, 0x6d, 0x32, 0xa8, 0xa4, 0x86, 0x8a, 0xf2, 0x0f, 0xab, 0x2e, 0x13, 0xca, 0x60, 0x9d, 0x5a, 0x77, 0x10, 0xa8, 0x27, 0x8a, 0xaf };
      std::vector<uint8_t> s = { 0x63, 0x75, 0x75, 0x5e, 0xff, 0x8d, 0x48, 0xaf, 0xb3, 0x26, 0x3b, 0x3b, 0x96, 0x98, 0x8a, 0x2a, 0xfd, 0x18, 0x1b, 0xa0, 0x61, 0x79, 0x3e, 0xa0, 0x09, 0x78, 0x3b, 0xb1, 0x59, 0x9d, 0x03, 0x94, 0x4d, 0x98, 0x76, 0x20, 0xa2, 0x66, 0x8a, 0xc9, 0x71, 0x4d, 0x6f, 0x2a, 0x21, 0xf7, 0xe5, 0x20, 0x0d, 0x63, 0x92, 0x3f, 0x42, 0xcb, 0x32, 0xe6, 0x33, 0x01, 0xc8, 0xde, 0x58, 0xc7, 0x0a, 0x20, 0x39, 0x10, 0x64, 0x0d, 0xa9, 0x67, 0xd0, 0x3f, 0x4f, 0x62, 0x92, 0xf6, 0xcb, 0x19, 0x97, 0x59, 0x82, 0x27, 0x90, 0xc0, 0xc5, 0xbc, 0xfb, 0x1d, 0x4f, 0xaa, 0x59, 0x46, 0x5c, 0x3d, 0xb2, 0xea, 0x1f, 0xff, 0xd5, 0xe5, 0x43, 0x33, 0x56, 0x32, 0xb7, 0x47, 0x45, 0xbf, 0x1e, 0x18, 0x47, 0x3c, 0x0a, 0x8b, 0x4a, 0x89, 0xde, 0xf6, 0xb2, 0x7e, 0xdf, 0x0d, 0x7d, 0x73, 0x5e, 0xe1, 0x3f, 0x88, 0x70, 0x41, 0xc9, 0xd8, 0xa9, 0x1e, 0x62, 0x18, 0x6a, 0x9a, 0x1e, 0x0b, 0x1a, 0xfb, 0x48, 0xe5, 0x77, 0xf6, 0x88, 0x7c, 0xa6, 0x1b, 0x7c, 0x1b, 0xb2, 0x6b, 0x4a, 0x8e, 0x2c, 0xc4, 0x64, 0xa9, 0xaf, 0x03, 0x44, 0x4b, 0x3d, 0xa5, 0xbe, 0xd0, 0x8b, 0x73, 0xf1, 0x26, 0x2b, 0xd3, 0xd6, 0x1f, 0x4c, 0x78, 0xf4, 0x9f, 0xac, 0x6a, 0x3b, 0xfc, 0x9e, 0x85, 0x48, 0xb4, 0xbb, 0xe6, 0x4c, 0xce, 0x6a, 0x60, 0x90, 0xfc, 0x48, 0x0e, 0xfd, 0x1f, 0x36, 0xc1, 0x8c, 0x10, 0xbc, 0x09, 0xbe, 0x9d, 0x95, 0x7a, 0x79, 0xf7, 0x07, 0xa1, 0x05, 0x77, 0xa1, 0xbf, 0x6e, 0x9e, 0x2d, 0x48, 0x49, 0x69, 0x3f, 0xa5, 0x8d, 0x88, 0x77, 0xc8, 0xf1, 0xe5, 0x51, 0x81, 0x95, 0x5d, 0x6c, 0x2b, 0x94, 0xb1, 0xd6, 0xd9, 0x40, 0x1b, 0x5f, 0xb8, 0x0c, 0xc3, 0x2b, 0x35, 0x89, 0x34, 0xfe, 0xc2, 0xae, 0xdb };

      test_pss<2048, SHA2<256>>(n, e, d, salt, msg, s);
    }

    SECTION("SHA512") {
      std::vector<uint8_t> salt = { 0x6f, 0x28, 0x41, 0x16, 0x6a, 0x64, 0x47, 0x1d, 0x4f, 0x0b, 0x8e, 0xd0, 0xdb, 0xb7, 0xdb, 0x32, 0x16, 0x1d, 0xa1, 0x3b };
      std::vector<uint8_t> msg = { 0x25, 0x24, 0x33, 0xd4, 0xb7, 0x2a, 0x33, 0xe1, 0xaa, 0x44, 0x4a, 0xa9, 0x68, 0x04, 0x54, 0xe9, 0xcd, 0xab, 0x20, 0x86, 0x37, 0xec, 0x21, 0x73, 0xdc, 0xf3, 0x66, 0xd5, 0x61, 0xa6, 0xcc, 0x65, 0xa8, 0x2b, 0x73, 0x16, 0xe9, 0xaa, 0x6e, 0xf9, 0x04, 0x54, 0xbf, 0x5d, 0x15, 0xa4, 0x82, 0x3a, 0x49, 0xe4, 0x68, 0xd0, 0xf1, 0xf4, 0x67, 0x8b, 0xd5, 0x47, 0xb0, 0x2a, 0xcb, 0x2e, 0xe2, 0x20, 0x88, 0x59, 0x7d, 0x3a, 0xb5, 0x9a, 0x99, 0x83, 0x46, 0xed, 0xd8, 0x65, 0x07, 0xb6, 0x99, 0x10, 0x77, 0x49, 0x6e, 0x20, 0xda, 0xaf, 0xd1, 0x79, 0x8a, 0xa8, 0x12, 0x76, 0x8e, 0xec, 0x94, 0x44, 0x6d, 0xb6, 0x39, 0x88, 0x44, 0x83, 0x1b, 0x48, 0x17, 0x17, 0x7d, 0x08, 0x65, 0xc2, 0x01, 0x33, 0xff, 0xe1, 0x1b, 0xbd, 0x1a, 0xa7, 0xc5, 0x07, 0xa2, 0x1e, 0x74, 0x03, 0xd1, 0x68, 0x4b, 0x98 };
      std::vector<uint8_t> s = { 0x2c, 0xdb, 0x0d, 0x5e, 0xa5, 0xf0, 0xaa, 0xd1, 0xf7, 0xaf, 0x81, 0x08, 0xbf, 0xf5, 0x6e, 0xec, 0x5c, 0x0d, 0xcd, 0x05, 0x22, 0xc5, 0xdc, 0x6a, 0xe4, 0xc6, 0xe0, 0xf6, 0x68, 0x21, 0xcd, 0xf6, 0x98, 0xcc, 0xfe, 0xac, 0xe6, 0x5f, 0xd6, 0xe4, 0x7f, 0x95, 0xfe, 0xbd, 0x87, 0x9e, 0x58, 0x0e, 0x5e, 0xe6, 0x48, 0x97, 0x2c, 0xc2, 0x65, 0xf9, 0xa1, 0x17, 0xfc, 0x72, 0x0d, 0xb4, 0xf2, 0x54, 0x5a, 0x43, 0x2e, 0xae, 0x24, 0xa3, 0x67, 0xb0, 0xaa, 0xa7, 0x0a, 0x01, 0x1a, 0xc8, 0xfd, 0xec, 0x94, 0xa9, 0x5c, 0x3c, 0xd4, 0x8c, 0xfa, 0x71, 0x02, 0xde, 0x8d, 0xc2, 0x6c, 0x87, 0x7e, 0x97, 0x46, 0x88, 0xb3, 0x91, 0x9d, 0xe6, 0xcf, 0x06, 0xe2, 0x70, 0x28, 0x99, 0x5a, 0xc8, 0x5d, 0xa8, 0x8c, 0xb3, 0x85, 0x1a, 0x57, 0x61, 0xe1, 0x7f, 0x21, 0x5e, 0x5c, 0x59, 0x3e, 0x13, 0xe4, 0x81, 0x08, 0x8c, 0x7d, 0x74, 0x7e, 0xcb, 0x34, 0xd3, 0xce, 0x61, 0xa5, 0xb5, 0x6e, 0xb2, 0xa6, 0x5b, 0xe5, 0x36, 0x33, 0x63, 0x29, 0x4e, 0xb3, 0x65, 0xf8, 0x3c, 0x4c, 0x70, 0x96, 0x44, 0xd8, 0x57, 0xe2, 0xcc, 0xb1, 0x4a, 0x58, 0x51, 0x72, 0x44, 0x20, 0xfc, 0x81, 0x17, 0x81, 0x44, 0xef, 0x3f, 0x9e, 0x11, 0x38, 0xb5, 0x75, 0x0e, 0xb7, 0x19, 0x6e, 0xba, 0x33, 0x19, 0xd7, 0x99, 0xc3, 0x49, 0x4a, 0x7e, 0x39, 0x91, 0x15, 0xa6, 0x2b, 0x1c, 0xa4, 0xf1, 0xd5, 0xda, 0x07, 0x9b, 0x49, 0x5d, 0x35, 0xfd, 0x65, 0x1a, 0x1d, 0xe7, 0x8d, 0x54, 0x00, 0x0b, 0x06, 0xbd, 0xd3, 0x12, 0x2d, 0x74, 0x04, 0x01, 0x3f, 0x2e, 0xd8, 0xfd, 0xf8, 0xa7, 0xd0, 0x12, 0xf9, 0x81, 0x2b, 0x8e, 0x4c, 0x2e, 0x0b, 0x24, 0x19, 0x2d, 0x5f, 0x89, 0x9d, 0x70, 0xa3, 0xcc, 0x5c, 0x7e, 0x08, 0xc8, 0x1b, 0xe7 };
      test_pss<2048, SHA2<512>>(n, e, d, salt, msg, s);
    }
  }
  SECTION("RSA 4096") {
    std::vector<uint8_t> n = { 0xcf, 0xca, 0xe4, 0x9f, 0x88, 0xb8, 0x0d, 0xc1, 0x21, 0x86, 0xd5, 0x3c, 0x57, 0x16, 0x2d, 0xbe, 0xcb, 0xa6, 0xe3, 0x48, 0x09, 0x4f, 0x9f, 0xb3, 0x74, 0x3e, 0x39, 0xd9, 0x9d, 0x53, 0x55, 0xd8, 0x7e, 0x3e, 0xfc, 0xa9, 0xd4, 0x88, 0xd3, 0x9d, 0x70, 0x56, 0x71, 0xe5, 0x86, 0x34, 0x30, 0x9c, 0xbd, 0x7c, 0xf5, 0x3f, 0xcc, 0xd5, 0x2d, 0x9a, 0x84, 0xed, 0xb9, 0x9f, 0xfd, 0xad, 0x06, 0x80, 0xe9, 0xec, 0x82, 0x6d, 0x62, 0x57, 0x28, 0x37, 0x07, 0x17, 0xb3, 0x93, 0x21, 0xc7, 0xd4, 0xb6, 0x88, 0x27, 0x85, 0xcf, 0x68, 0x84, 0x27, 0x5f, 0x6c, 0x7b, 0x6d, 0x68, 0x1b, 0xfa, 0x71, 0x05, 0x93, 0x67, 0x9e, 0x99, 0xb6, 0x7d, 0x5b, 0xc2, 0x81, 0x21, 0xdd, 0x60, 0x36, 0x17, 0xdc, 0x8c, 0xfd, 0xb2, 0x55, 0x7c, 0x2a, 0x04, 0x53, 0x38, 0x93, 0xf5, 0x93, 0xf0, 0xf7, 0xe5, 0x9c, 0xbe, 0x6d, 0x46, 0x62, 0x3d, 0x22, 0x64, 0x2a, 0x71, 0x61, 0xa4, 0xc6, 0x85, 0xb2, 0x93, 0xc7, 0xed, 0xcc, 0x9a, 0xae, 0xc4, 0x8e, 0x38, 0x10, 0xec, 0x74, 0xa8, 0x84, 0xa4, 0x11, 0x08, 0x61, 0x0d, 0x00, 0x0b, 0x59, 0x1f, 0xbf, 0x5d, 0xa4, 0x4b, 0x55, 0x01, 0xe6, 0x37, 0x81, 0x26, 0x4e, 0xdf, 0x3c, 0x73, 0x70, 0x63, 0x21, 0xec, 0xf4, 0x4d, 0x0e, 0x14, 0xb5, 0x93, 0x2a, 0x2d, 0x69, 0xca, 0x3d, 0x18, 0x0c, 0x5c, 0xee, 0x86, 0xb4, 0xcc, 0xad, 0x85, 0x0c, 0x76, 0x6e, 0x0b, 0xeb, 0x5f, 0x20, 0xe6, 0xb1, 0x42, 0x05, 0x5d, 0x55, 0x1a, 0xeb, 0x45, 0x3b, 0xd0, 0x99, 0xea, 0xc6, 0x7e, 0xb9, 0x2c, 0xf1, 0x3e, 0x34, 0xef, 0x0d, 0x0e, 0x34, 0xfc, 0x59, 0x9a, 0x6e, 0x5d, 0x4d, 0x14, 0xf7, 0x4e, 0x08, 0x19, 0x0c, 0x66, 0xc6, 0x6a, 0xd3, 0x47, 0x3d, 0xe9, 0xae, 0x8f, 0x53, 0xdd, 0x2c, 0x1c, 0x0c, 0x41, 0xf4, 0xb4, 0xa8, 0xd4, 0x69, 0x0f, 0x4b, 0x77, 0x35, 0x4c, 0x76, 0xe0, 0x5a, 0xb7, 0x6b, 0x7a, 0x6c, 0x7c, 0x9e, 0xdf, 0x09, 0x55, 0xfe, 0xe7, 0x99, 0xa2, 0xbb, 0x42, 0xc8, 0x6c, 0x6a, 0x06, 0x63, 0x13, 0x98, 0xd3, 0x8c, 0xce, 0xb7, 0x1e, 0xc9, 0xaa, 0xa9, 0xa0, 0xfb, 0x83, 0x85, 0x0f, 0x62, 0x34, 0x2f, 0x3f, 0x78, 0x1f, 0x9d, 0x45, 0x32, 0x29, 0xb1, 0xa7, 0x09, 0xbb, 0xce, 0x83, 0xa4, 0x4c, 0x22, 0x5e, 0xbf, 0xfd, 0x4f, 0x51, 0x8f, 0x94, 0xa7, 0x93, 0x5f, 0x46, 0x69, 0xf6, 0x5d, 0x02, 0xff, 0x3d, 0xef, 0xbb, 0xd1, 0xd5, 0xef, 0xd9, 0x19, 0x13, 0x65, 0x80, 0x8c, 0xdf, 0x94, 0x60, 0x37, 0x1e, 0xde, 0x1e, 0xae, 0x73, 0x5a, 0xf0, 0x3f, 0x21, 0x43, 0x12, 0x39, 0xd5, 0xcd, 0x57, 0xcc, 0x0c, 0xc8, 0x8f, 0xb3, 0x96, 0x5d, 0x18, 0x7e, 0xba, 0x98, 0x35, 0x94, 0x09, 0xaa, 0xa9, 0x44, 0xa7, 0xaf, 0x8e, 0x85, 0xe2, 0x0b, 0x67, 0xc4, 0x3c, 0x82, 0xe7, 0x8f, 0xa9, 0x67, 0xfc, 0x0d, 0x62, 0x9b, 0xcd, 0x74, 0x83, 0xd1, 0x7d, 0xca, 0xa2, 0x59, 0x15, 0x57, 0x1a, 0x15, 0xc3, 0xf0, 0xc7, 0x30, 0xe8, 0x10, 0x95, 0x13, 0x9d, 0x71, 0xa2, 0x88, 0x58, 0xdd, 0x9d, 0x83, 0xb6, 0x5b, 0xf9, 0xc9, 0x27, 0x3a, 0x8a, 0x40, 0xb1, 0x2a, 0x2c, 0x87, 0x10, 0x7a, 0x71, 0xf9, 0x84, 0x81, 0x8f, 0x7d, 0xc7, 0x66, 0x37, 0x4d, 0x31, 0xb4, 0xc3, 0xa1, 0xd2, 0x84, 0xad, 0xb2, 0xa1, 0x7f, 0x8a, 0xc8, 0x5d, 0xbe, 0x3f, 0x58, 0xcf, 0x78, 0xb1, 0x4c, 0x0f, 0xdc, 0xe0, 0x0a, 0x79, 0xda, 0xf3, 0x48, 0xaa, 0x05, 0x57, 0x29, 0x0e, 0xf5, 0xf9, 0xdd, 0x30, 0x5c, 0x15, 0xfa, 0x73, 0xd4, 0x0c, 0x68, 0x22, 0xb7, 0x5f, 0xda, 0x13, 0xec, 0x43 };
    std::vector<uint8_t> e = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01 };
    std::vector<uint8_t> d = { 0x06, 0xa4, 0x31, 0x7d, 0x22, 0x88, 0x34, 0xc8, 0x56, 0x23, 0x52, 0x70, 0x19, 0xf3, 0x22, 0x30, 0x80, 0x49, 0xd6, 0x91, 0xd8, 0x2f, 0xac, 0xa7, 0x0b, 0xb1, 0x6c, 0x1f, 0xec, 0x76, 0x06, 0xbf, 0x0d, 0xff, 0x42, 0xb6, 0xc5, 0x8d, 0x94, 0xab, 0x3f, 0x8a, 0x99, 0x1c, 0x00, 0xec, 0xc2, 0x1b, 0xab, 0x0d, 0x72, 0x0e, 0x96, 0xa4, 0x14, 0x4f, 0xba, 0xad, 0x43, 0xca, 0xe7, 0xf7, 0x69, 0x1c, 0x78, 0x5d, 0x90, 0x28, 0x4c, 0x30, 0x5a, 0x4a, 0x07, 0xf6, 0xab, 0x4d, 0x54, 0x93, 0x12, 0x80, 0x13, 0x07, 0x50, 0x5b, 0x8f, 0x62, 0x49, 0xef, 0xde, 0xd9, 0x18, 0x67, 0x6f, 0x72, 0xd3, 0x11, 0xf3, 0xe2, 0xd2, 0xa0, 0x39, 0xc3, 0x9f, 0xf4, 0x83, 0x89, 0x6a, 0xe3, 0x47, 0x01, 0xfe, 0xe6, 0x9d, 0x65, 0x34, 0x73, 0x97, 0x7e, 0xde, 0x8f, 0x67, 0x0b, 0x3e, 0x58, 0x96, 0xa9, 0x1c, 0x18, 0x14, 0xb3, 0x5f, 0x33, 0x1d, 0x04, 0xf3, 0xe6, 0x53, 0xd1, 0xf4, 0x6b, 0xbe, 0xdd, 0x6c, 0xfd, 0x1e, 0x16, 0x58, 0xe7, 0xa7, 0x5e, 0xb0, 0xb6, 0x73, 0x5e, 0xbf, 0x7e, 0x8e, 0xf2, 0x24, 0x47, 0xf4, 0xc1, 0xbd, 0x6e, 0x2a, 0x56, 0x4f, 0xdd, 0xfd, 0xda, 0xe5, 0xaf, 0x78, 0x77, 0xef, 0xa5, 0x6a, 0xef, 0xe0, 0x49, 0x0a, 0xd8, 0x8b, 0xfb, 0xba, 0x80, 0xd1, 0x9c, 0xe1, 0x32, 0xe5, 0x0d, 0x60, 0x63, 0xd8, 0x61, 0x50, 0x03, 0xb6, 0x30, 0xf9, 0xe0, 0x25, 0x6f, 0x28, 0xed, 0x45, 0xef, 0x45, 0xc4, 0x99, 0xd3, 0x1b, 0xb6, 0x1e, 0xa0, 0xe6, 0xf6, 0xd0, 0xdb, 0xf0, 0xa4, 0xc9, 0xb0, 0xb0, 0x87, 0xcd, 0xde, 0x1d, 0xcb, 0x00, 0xdb, 0xd2, 0x0d, 0xb9, 0x6a, 0x1a, 0x2f, 0x99, 0x3b, 0x1b, 0xa7, 0x14, 0x28, 0x83, 0x76, 0x4a, 0xce, 0x8c, 0x9a, 0x30, 0xfc, 0x65, 0xbb, 0xe7, 0x03, 0x92, 0x98, 0x06, 0x65, 0xa9, 0x0e, 0x54, 0x38, 0x52, 0xfa, 0x7e, 0x53, 0xa3, 0xf0, 0x1c, 0xde, 0x58, 0xa4, 0x92, 0xfd, 0x35, 0xb9, 0xde, 0xe9, 0x1e, 0xae, 0x2c, 0xd6, 0xa5, 0x47, 0x1e, 0x87, 0x78, 0xd7, 0x2f, 0x94, 0x66, 0x18, 0xda, 0x97, 0xa2, 0xc7, 0x5e, 0xb7, 0xf7, 0xc7, 0x22, 0x46, 0x0e, 0xcd, 0x84, 0xca, 0xe7, 0x4c, 0x0d, 0x36, 0x70, 0x0b, 0x80, 0x38, 0x18, 0x3e, 0x2d, 0x85, 0x2e, 0xcc, 0xbb, 0xe4, 0x99, 0x87, 0x2e, 0x44, 0x92, 0x77, 0x68, 0xb4, 0x12, 0x23, 0xf9, 0x10, 0xf2, 0x76, 0x13, 0x21, 0xcf, 0x46, 0x9f, 0x73, 0xfc, 0xd2, 0x08, 0x3c, 0x0a, 0x64, 0x47, 0x0b, 0x05, 0x69, 0xed, 0xcd, 0x00, 0x73, 0xc0, 0x28, 0xe5, 0x21, 0x24, 0x62, 0xfa, 0x13, 0xc1, 0xf2, 0xe0, 0x4b, 0x2d, 0x75, 0x42, 0x40, 0xac, 0xd2, 0xae, 0x27, 0xbf, 0x6c, 0x28, 0x7c, 0xe3, 0xfa, 0xae, 0x65, 0x58, 0x65, 0x38, 0xd4, 0x35, 0xe8, 0x38, 0x38, 0xdf, 0x1c, 0xae, 0xcf, 0x3b, 0xc8, 0xd5, 0x8e, 0x30, 0xa4, 0x6d, 0x86, 0xee, 0xba, 0x4a, 0x26, 0x7a, 0x33, 0xeb, 0x60, 0x3d, 0x4a, 0x81, 0x2a, 0xa4, 0xfb, 0xa3, 0xc6, 0xcc, 0xb1, 0x0e, 0xcb, 0x6b, 0x3b, 0x16, 0xae, 0x07, 0x93, 0x95, 0x22, 0xf8, 0xb7, 0xb0, 0x89, 0xf0, 0xaf, 0x72, 0x31, 0x01, 0x43, 0x19, 0x26, 0x3c, 0xa6, 0x93, 0xf5, 0xba, 0xe5, 0x58, 0x5d, 0x54, 0x2b, 0xb1, 0x4d, 0x5e, 0x9f, 0x80, 0x74, 0x78, 0xdf, 0x37, 0x7b, 0x27, 0x80, 0xa4, 0xe5, 0xda, 0x2d, 0xa6, 0xd8, 0x5e, 0x4a, 0x0a, 0x08, 0x31, 0x6c, 0xa0, 0x08, 0x82, 0x39, 0xd7, 0x77, 0xd8, 0xce, 0x27, 0x5c, 0xa2, 0xbb, 0x11, 0xff, 0x04, 0x96, 0xea, 0x2e, 0x94, 0x3f, 0x2e, 0x77, 0xfc, 0x8e, 0x0f, 0xcd, 0xe0, 0x7b, 0xd3, 0x55, 0xde, 0xe1 };

    SECTION("SHA256") {
      std::vector<uint8_t> salt = { 0x6f, 0x28, 0x41, 0x16, 0x6a, 0x64, 0x47, 0x1d, 0x4f, 0x0b, 0x8e, 0xd0, 0xdb, 0xb7, 0xdb, 0x32, 0x16, 0x1d, 0xa1, 0x3b };
      std::vector<uint8_t> msg = { 0x46, 0x6d, 0x26, 0x21, 0xac, 0xc8, 0xa9, 0x1c, 0x72, 0x93, 0x34, 0xf1, 0xca, 0x43, 0x3b, 0xdb, 0x56, 0x05, 0x05, 0x8d, 0x48, 0x51, 0xf8, 0x6c, 0xc8, 0xc2, 0x17, 0xfb, 0x96, 0x25, 0xc9, 0x96, 0xf0, 0xd0, 0xdc, 0x64, 0xb6, 0x35, 0xc9, 0x87, 0xcc, 0xb6, 0x3a, 0x95, 0xc0, 0xbb, 0xc9, 0x4c, 0xac, 0x02, 0x0b, 0x81, 0x5e, 0x37, 0xcd, 0x5a, 0xb7, 0xc5, 0x9d, 0xbd, 0x51, 0xeb, 0x8d, 0x08, 0x64, 0x12, 0x33, 0x03, 0xeb, 0x5e, 0xf4, 0x13, 0x02, 0x83, 0x83, 0xb0, 0x93, 0xda, 0xa4, 0x18, 0x31, 0xb4, 0x36, 0x45, 0x44, 0xee, 0x70, 0x1d, 0x67, 0xc5, 0x6b, 0xea, 0x0e, 0xec, 0xe0, 0x09, 0x6c, 0xdc, 0x34, 0xe6, 0x94, 0x6c, 0xb1, 0x28, 0xde, 0xa1, 0x17, 0x28, 0x8c, 0xc7, 0x53, 0xa8, 0xad, 0xc0, 0x8e, 0xc2, 0x42, 0x9d, 0x69, 0x1e, 0xa0, 0x6b, 0x87, 0x68, 0x15, 0x4f, 0x4d, 0x01 };
      std::vector<uint8_t> s = { 0x2e, 0x51, 0x2f, 0x73, 0xd1, 0x98, 0xe6, 0x23, 0xaf, 0xe0, 0x19, 0xbd, 0x4c, 0xea, 0x91, 0x92, 0xff, 0x8b, 0x24, 0xab, 0x55, 0x50, 0x99, 0xd3, 0x1b, 0xd5, 0x2d, 0x70, 0x5f, 0xc8, 0x08, 0x22, 0x9a, 0x26, 0x9b, 0xf7, 0x49, 0xc8, 0x06, 0x1a, 0x3d, 0xc7, 0xff, 0xae, 0x9e, 0xf7, 0xc6, 0xbd, 0xcd, 0x8c, 0x34, 0x91, 0x0f, 0x92, 0xf0, 0xa0, 0xfc, 0xd6, 0xd7, 0x30, 0x17, 0xca, 0x33, 0x88, 0xca, 0x5e, 0x99, 0xa1, 0x73, 0x5e, 0x00, 0x5f, 0xf5, 0xd5, 0xea, 0xde, 0x3e, 0xc0, 0xea, 0x0c, 0x24, 0x36, 0xf0, 0xe7, 0x8b, 0x19, 0x7c, 0x2d, 0x99, 0x9b, 0xa4, 0x35, 0x1b, 0x9e, 0x37, 0xa0, 0x91, 0x95, 0x50, 0x4b, 0x63, 0xa4, 0x27, 0x62, 0xbe, 0xa2, 0x2d, 0x30, 0x7a, 0x03, 0x28, 0xfc, 0x9c, 0x80, 0xac, 0xdc, 0x28, 0xfc, 0x8f, 0x40, 0x50, 0xe2, 0x5f, 0xbd, 0x58, 0x90, 0x23, 0x30, 0x28, 0xf9, 0x7e, 0xa3, 0xa2, 0x66, 0x9f, 0xf4, 0xd5, 0xf4, 0x23, 0x2c, 0x1e, 0x48, 0x57, 0x14, 0x99, 0xaf, 0x28, 0xed, 0x6f, 0x5a, 0x92, 0xe7, 0x93, 0x6d, 0xe3, 0x9d, 0x91, 0x3e, 0x12, 0xc5, 0xce, 0xf5, 0x1e, 0x25, 0xf9, 0x0a, 0x1e, 0x90, 0x3f, 0x3f, 0x60, 0xa6, 0xa9, 0xcd, 0xdb, 0xc5, 0x65, 0x64, 0xb1, 0x46, 0xac, 0xa6, 0xaf, 0x62, 0x36, 0xb8, 0x99, 0xc2, 0xcb, 0x72, 0x23, 0xa6, 0x94, 0x1f, 0x0b, 0xea, 0xa3, 0xaa, 0x78, 0x7b, 0x23, 0x33, 0xe4, 0xf3, 0xe6, 0x6b, 0x33, 0x4b, 0x99, 0xb9, 0x08, 0x25, 0x15, 0x3e, 0xbd, 0x00, 0x95, 0xf2, 0x76, 0x91, 0x88, 0x0f, 0x44, 0xe4, 0xe7, 0x71, 0x35, 0xf2, 0x6d, 0xf3, 0x76, 0xe2, 0x61, 0xad, 0xfe, 0x0d, 0x83, 0x54, 0xcf, 0xa1, 0x5b, 0x49, 0x13, 0x8d, 0x62, 0x4d, 0x9f, 0x62, 0xa9, 0x75, 0x12, 0x21, 0xee, 0x05, 0x98, 0x09, 0x78, 0x91, 0xc9, 0x86, 0x4a, 0xd3, 0x65, 0x1e, 0x89, 0x72, 0x3b, 0xc9, 0xec, 0x60, 0x86, 0xf5, 0x71, 0xe1, 0x99, 0x61, 0x9c, 0xeb, 0x67, 0x20, 0xab, 0x5a, 0x49, 0x98, 0x25, 0x4c, 0xb8, 0x07, 0xdc, 0xe7, 0x5a, 0x5a, 0x52, 0x03, 0xd3, 0x8a, 0x9f, 0x5d, 0x56, 0xad, 0xee, 0x42, 0x39, 0xff, 0x50, 0xce, 0xfe, 0x3e, 0x92, 0x7e, 0xba, 0x91, 0xde, 0x7e, 0x1f, 0x8e, 0x1a, 0xe8, 0xb0, 0x50, 0x5c, 0x07, 0x77, 0x88, 0x37, 0x2a, 0xf7, 0xd8, 0xef, 0x00, 0x73, 0x5c, 0xc5, 0x31, 0xfd, 0x46, 0xdb, 0xe8, 0x67, 0x02, 0xac, 0x49, 0x17, 0x1f, 0x0a, 0x92, 0x1f, 0x46, 0x26, 0x44, 0x2a, 0xe9, 0x60, 0xe9, 0x72, 0xa5, 0x59, 0x4e, 0xe3, 0xbc, 0xbf, 0xbf, 0x68, 0x7c, 0xd9, 0x6e, 0xd3, 0x00, 0xaa, 0x9d, 0xf1, 0xb9, 0x48, 0x76, 0x07, 0xb5, 0xba, 0xe0, 0xf1, 0xab, 0xec, 0xbc, 0x1d, 0x22, 0x91, 0xfe, 0x93, 0xb9, 0xf8, 0xa0, 0x91, 0xff, 0xac, 0x84, 0x69, 0xb0, 0xf0, 0x0b, 0xa5, 0x61, 0xf0, 0x62, 0x8f, 0x5e, 0x00, 0x4e, 0xd1, 0xfd, 0x87, 0x13, 0x65, 0x0e, 0x14, 0x7c, 0x4b, 0x2c, 0xab, 0x7f, 0x4d, 0x69, 0xa4, 0xad, 0x57, 0xb1, 0x45, 0xc1, 0xe5, 0xe4, 0xc1, 0x41, 0x2e, 0x86, 0xfb, 0xbd, 0xa5, 0xa6, 0x09, 0x6f, 0x66, 0x29, 0x32, 0x03, 0x20, 0x7e, 0x35, 0x09, 0x8b, 0xf9, 0x4d, 0xaf, 0xff, 0x75, 0xed, 0x09, 0x4d, 0x10, 0xe6, 0x03, 0x4c, 0xd2, 0x21, 0x79, 0xd9, 0x46, 0x55, 0x00, 0x4f, 0xa4, 0xbf, 0x4d, 0xe7, 0x74, 0x80, 0x7b, 0x6f, 0x5c, 0xd2, 0x7d, 0x90, 0x25, 0x54, 0x68, 0xcf, 0x01, 0xdb, 0x7b, 0x6f, 0x82, 0x60, 0x7d, 0xf5, 0x97, 0xf7, 0x2d, 0x1f, 0x9c, 0x9c, 0x91, 0xd1, 0x77, 0x40, 0xa1, 0x4a, 0x48, 0x16, 0xae, 0x65, 0xe6, 0x3f, 0xde, 0x48, 0x0d };
      test_pss<4096, SHA2<256>>(n, e, d, salt, msg, s);
    }

    SECTION("SHA512") {
      std::vector<uint8_t> salt = { 0x6f, 0x28, 0x41, 0x16, 0x6a, 0x64, 0x47, 0x1d, 0x4f, 0x0b, 0x8e, 0xd0, 0xdb, 0xb7, 0xdb, 0x32, 0x16, 0x1d, 0xa1, 0x3b };
      std::vector<uint8_t> msg = { 0xfc, 0x5b, 0x9d, 0xa7, 0x4a, 0x8a, 0xff, 0xf5, 0x3e, 0x53, 0xf7, 0x55, 0x8b, 0x69, 0xfc, 0xad, 0x8a, 0x92, 0x4d, 0x94, 0x8c, 0xac, 0xe2, 0x6f, 0x6e, 0xee, 0xa2, 0xd9, 0x6e, 0x71, 0xd6, 0x49, 0x3c, 0xef, 0xde, 0xee, 0x55, 0xca, 0x22, 0xde, 0x8c, 0x50, 0x4c, 0x70, 0xe9, 0x3d, 0xb5, 0xe6, 0xb7, 0x81, 0x1c, 0x50, 0xd9, 0x44, 0x9e, 0xad, 0x5d, 0x28, 0xe2, 0x52, 0x54, 0xce, 0x95, 0x90, 0xe0, 0x9b, 0x16, 0x91, 0x8e, 0xbc, 0x72, 0x83, 0xe6, 0x67, 0x92, 0xf8, 0x41, 0x64, 0xb3, 0x8d, 0xdb, 0xcd, 0x17, 0xca, 0x29, 0x12, 0xfa, 0x4a, 0x6d, 0x3f, 0xc8, 0x1c, 0x87, 0x82, 0x8d, 0x68, 0x0e, 0xe8, 0xad, 0x56, 0x9f, 0x67, 0xd5, 0x2b, 0x75, 0x21, 0x31, 0xb6, 0x3a, 0xe7, 0xe0, 0xea, 0x1d, 0xfc, 0xa5, 0xcc, 0x25, 0x1c, 0xdf, 0x90, 0xc5, 0xbd, 0xbb, 0xfe, 0xb0, 0x95, 0xa8, 0x1b };
      std::vector<uint8_t> s = { 0x6e, 0xdf, 0xb6, 0xbf, 0xb2, 0x0d, 0xa2, 0x62, 0x1e, 0x7c, 0xa0, 0xb8, 0xe1, 0x3b, 0xfc, 0x38, 0x01, 0xd8, 0xbc, 0xb4, 0x3e, 0xf3, 0x82, 0x2b, 0xe9, 0x60, 0xb9, 0x6a, 0x67, 0xd3, 0xe8, 0xaf, 0xbb, 0xe2, 0xef, 0x22, 0xe2, 0x06, 0xb3, 0x28, 0xce, 0x99, 0xdd, 0x8f, 0x97, 0x58, 0x05, 0x2d, 0x42, 0xa8, 0xee, 0x93, 0xe1, 0x6d, 0x8e, 0x16, 0x0a, 0x50, 0x68, 0x7e, 0x8f, 0xfc, 0xe7, 0x2d, 0x25, 0x86, 0x10, 0x06, 0x4e, 0xbd, 0xe4, 0xc4, 0xcc, 0x2a, 0xb9, 0x6c, 0x8e, 0x51, 0x6e, 0xc2, 0xc1, 0xee, 0xd8, 0x16, 0xc8, 0xe6, 0xac, 0x53, 0x7a, 0x05, 0x70, 0xc9, 0xef, 0xf8, 0x1a, 0x38, 0x14, 0x7b, 0xcd, 0x8f, 0x47, 0x47, 0x39, 0x06, 0x76, 0xf9, 0xd7, 0x55, 0xf6, 0x13, 0x68, 0x7a, 0xc5, 0x9d, 0xba, 0xc1, 0x4f, 0x69, 0xca, 0x6e, 0x56, 0xa2, 0x67, 0x27, 0x69, 0x9f, 0xa1, 0x1c, 0x20, 0x0e, 0xb7, 0x73, 0x39, 0xea, 0xd5, 0x6f, 0xc6, 0x88, 0x3a, 0xcf, 0x9b, 0x92, 0xc6, 0xde, 0xb6, 0xf4, 0xd7, 0x9f, 0x82, 0xcc, 0xdc, 0x49, 0x3f, 0xed, 0xc6, 0x16, 0x5f, 0x78, 0xc1, 0x74, 0xad, 0xcf, 0x32, 0x94, 0x1e, 0xeb, 0x23, 0x7a, 0x4a, 0xe3, 0x69, 0xdb, 0xba, 0xfb, 0x45, 0x53, 0xc9, 0x8e, 0x41, 0x38, 0x23, 0xf6, 0xf4, 0x6d, 0xa0, 0xd4, 0x7d, 0x47, 0xa1, 0x64, 0xb7, 0x92, 0xaa, 0xf1, 0x32, 0x4a, 0x8b, 0xe4, 0xf0, 0x16, 0x01, 0xbc, 0xeb, 0x80, 0x9f, 0x8c, 0x08, 0xf3, 0x45, 0x8b, 0x1d, 0xe2, 0xc6, 0x37, 0x8c, 0xf9, 0x3f, 0xb2, 0x93, 0x21, 0x2f, 0x6b, 0xd4, 0xa7, 0xb1, 0xfd, 0x1b, 0xfa, 0x14, 0xa1, 0xaf, 0x29, 0x57, 0x5a, 0x5e, 0xcc, 0x42, 0x81, 0x42, 0x01, 0x79, 0x75, 0x8e, 0x96, 0xb4, 0x46, 0x5e, 0xc0, 0x7f, 0x6c, 0xce, 0x4e, 0x5e, 0x5c, 0x23, 0x07, 0xd5, 0x31, 0xe4, 0x00, 0xe4, 0x94, 0x72, 0x5e, 0xb7, 0xdc, 0xeb, 0x1d, 0x8d, 0xac, 0x10, 0x00, 0xd9, 0x2f, 0x62, 0xf3, 0x19, 0x53, 0x40, 0x63, 0xc0, 0x1a, 0xec, 0x9c, 0x6e, 0xc0, 0xc7, 0x67, 0x53, 0x51, 0xf2, 0x88, 0x3e, 0x46, 0x2b, 0x04, 0x54, 0xdb, 0x36, 0x4f, 0x03, 0x70, 0x0d, 0x65, 0x93, 0xc9, 0xbe, 0x19, 0x5f, 0xbe, 0xa5, 0x80, 0x0e, 0xbb, 0x81, 0x57, 0x8c, 0x76, 0x54, 0x09, 0xac, 0x2c, 0x37, 0xf7, 0x8f, 0xab, 0xe8, 0x78, 0x3c, 0x5d, 0x32, 0x4f, 0xa4, 0xdf, 0xab, 0xe4, 0xf1, 0x92, 0x86, 0x6e, 0x34, 0x03, 0x79, 0x01, 0x61, 0x53, 0x04, 0x23, 0x7f, 0x08, 0x02, 0x8a, 0x75, 0xf0, 0x0a, 0x39, 0x04, 0xbe, 0xa0, 0x32, 0x19, 0xef, 0x9d, 0xbf, 0xeb, 0x48, 0xd1, 0x0e, 0xc5, 0x9d, 0x48, 0x1e, 0xb0, 0x42, 0x9c, 0xfc, 0x9a, 0xe8, 0x35, 0xcc, 0x57, 0x83, 0x77, 0xe6, 0x10, 0x23, 0xd5, 0xce, 0xed, 0xfd, 0x3d, 0x0a, 0x05, 0xac, 0xed, 0xdb, 0x27, 0x4c, 0x13, 0x78, 0x2d, 0xda, 0x92, 0x99, 0xd6, 0x19, 0x75, 0x19, 0xe1, 0x47, 0x91, 0x20, 0x8f, 0x8d, 0x86, 0xd6, 0x3e, 0x0a, 0xb7, 0xfb, 0x42, 0xa1, 0xe1, 0x4f, 0x8f, 0x37, 0xf4, 0x97, 0x32, 0xe2, 0x3d, 0x4b, 0x7d, 0x4f, 0x07, 0xcd, 0x0b, 0xc8, 0x28, 0x64, 0x9a, 0x12, 0x74, 0x8e, 0x8d, 0x70, 0xf5, 0x36, 0x83, 0x58, 0x0b, 0xca, 0x87, 0x29, 0x09, 0x92, 0xa3, 0x49, 0x73, 0x03, 0x70, 0xbb, 0xed, 0x6e, 0xd7, 0x43, 0xe7, 0x05, 0x75, 0x97, 0x34, 0x87, 0x2c, 0x54, 0xff, 0x03, 0xc1, 0xa9, 0x70, 0x37, 0xa7, 0xb9, 0xee, 0x3c, 0x8c, 0x42, 0xd1, 0x2c, 0x3e, 0xbe, 0x0c, 0x1b, 0xf3, 0xb4, 0x28, 0x54, 0xd0, 0x4a, 0x91, 0x77, 0xd1, 0xa2, 0x40, 0x00, 0xbd, 0x38, 0x8f, 0xa2, 0x89, 0xfd, 0x77, 0xd5 };
      test_pss<4096, SHA2<512>>(n, e, d, salt, msg, s);
    }
  }
}
}

