#include <catch.hpp>
#include "hkdf.h"
#include "sha2.h"

struct MyCipher {
  static constexpr size_t size = 16;
  static constexpr size_t ivsize = 12;
  static constexpr size_t keysize = 16;
};

TEST_CASE("hkdf single test vector", "[HKDF]") {
  std::vector<uint8_t> shared = { 0xdf, 0x4a, 0x29, 0x1b, 0xaa, 0x1e, 0xb7, 0xcf, 0xa6, 0x93, 0x4b, 0x29, 0xb4, 0x74, 0xba, 0xad, 0x26, 0x97, 0xe2, 0x9f, 0x1f, 0x92, 0x0d, 0xcc, 0x77, 0xc8, 0xa0, 0xa0, 0x88, 0x44, 0x76, 0x24 };
  std::vector<uint8_t> handshake_secret = { 0xfb, 0x9f, 0xc8, 0x06, 0x89, 0xb3, 0xa5, 0xd0, 0x2c, 0x33, 0x24, 0x3b, 0xf6, 0x9a, 0x1b, 0x1b, 0x20, 0x70, 0x55, 0x88, 0xa7, 0x94, 0x30, 0x4a, 0x6e, 0x71, 0x20, 0x15, 0x5e, 0xdf, 0x14, 0x9a };

  auto hs = HKDF_HandshakeSecret<SHA256>(shared);
  CHECK(hs.data == handshake_secret);

  std::vector<uint8_t> helloHash = { 0xda, 0x75, 0xce, 0x11, 0x39, 0xac, 0x80, 0xda, 0xe4, 0x04, 0x4d, 0xa9, 0x32, 0x35, 0x0c, 0xf6, 0x5c, 0x97, 0xcc, 0xc9, 0xe3, 0x3f, 0x1e, 0x6f, 0x7d, 0x2d, 0x4b, 0x18, 0xb7, 0x36, 0xff, 0xd5 };

  std::vector<uint8_t> handshake_c_traffic = { 0xff, 0x0e, 0x5b, 0x96, 0x52, 0x91, 0xc6, 0x08, 0xc1, 0xe8, 0xcd, 0x26, 0x7e, 0xef, 0xc0, 0xaf, 0xcc, 0x5e, 0x98, 0xa2, 0x78, 0x63, 0x73, 0xf0, 0xdb, 0x47, 0xb0, 0x47, 0x86, 0xd7, 0x2a, 0xea };
  std::vector c_tr = HKDF_Expand_Label<SHA256>(handshake_secret, "c hs traffic", helloHash, 32);
  CHECK(c_tr == handshake_c_traffic);
  std::vector<uint8_t> handshake_s_traffic = { 0xa2, 0x06, 0x72, 0x65, 0xe7, 0xf0, 0x65, 0x2a, 0x92, 0x3d, 0x5d, 0x72, 0xab, 0x04, 0x67, 0xc4, 0x61, 0x32, 0xee, 0xb9, 0x68, 0xb6, 0xa3, 0x2d, 0x31, 0x1c, 0x80, 0x58, 0x68, 0x54, 0x88, 0x14 };
  std::vector s_tr = HKDF_Expand_Label<SHA256>(handshake_secret, "s hs traffic", helloHash, 32);
  CHECK(s_tr == handshake_s_traffic);

  std::vector<uint8_t> handshake_c_key = { 0x71, 0x54, 0xf3, 0x14, 0xe6, 0xbe, 0x7d, 0xc0, 0x08, 0xdf, 0x2c, 0x83, 0x2b, 0xaa, 0x1d, 0x39 };
  std::vector<uint8_t> handshake_s_key = { 0x84, 0x47, 0x80, 0xa7, 0xac, 0xad, 0x9f, 0x98, 0x0f, 0xa2, 0x5c, 0x11, 0x4e, 0x43, 0x40, 0x2a };
  std::vector<uint8_t> handshake_c_iv = { 0x71, 0xab, 0xc2, 0xca, 0xe4, 0xc6, 0x99, 0xd4, 0x7c, 0x60, 0x02, 0x68 };
  std::vector<uint8_t> handshake_s_iv = { 0x4c, 0x04, 0x2d, 0xdc, 0x12, 0x0a, 0x38, 0xd1, 0x41, 0x7f, 0xc8, 0x15 };

  key_iv_pair<MyCipher> server = hs.get_key_iv<MyCipher>(helloHash, false, true);
  key_iv_pair<MyCipher> client = hs.get_key_iv<MyCipher>(helloHash, true, true);

  CHECK(server.key == handshake_s_key);
  CHECK(server.iv == handshake_s_iv);
  CHECK(client.key == handshake_c_key);
  CHECK(client.iv == handshake_c_iv);

	
  std::vector<uint8_t> hshash = { 0x22, 0x84, 0x4b, 0x93, 0x0e, 0x5e, 0x0a, 0x59, 0xa0, 0x9d, 0x5a, 0xc3, 0x5f, 0xc0, 0x32, 0xfc, 0x91, 0x16, 0x3b, 0x19, 0x38, 0x74, 0xa2, 0x65, 0x23, 0x6e, 0x56, 0x80, 0x77, 0x37, 0x8d, 0x8b };
  auto ms = HKDF_MasterSecret<SHA256>(hs);
  key_iv_pair<MyCipher> serverM = ms.get_key_iv<MyCipher>(hshash, false);
  key_iv_pair<MyCipher> clientM = ms.get_key_iv<MyCipher>(hshash, true);



  std::vector<uint8_t> session_c_key = { 0x49, 0x13, 0x4b, 0x95, 0x32, 0x8f, 0x27, 0x9f, 0x01, 0x83, 0x86, 0x05, 0x89, 0xac, 0x67, 0x07 };
  std::vector<uint8_t> session_s_key = { 0x0b, 0x6d, 0x22, 0xc8, 0xff, 0x68, 0x09, 0x7e, 0xa8, 0x71, 0xc6, 0x72, 0x07, 0x37, 0x73, 0xbf };
  std::vector<uint8_t> session_c_iv = { 0xbc, 0x4d, 0xd5, 0xf7, 0xb9, 0x8a, 0xcf, 0xf8, 0x54, 0x66, 0x26, 0x1d }; 
  std::vector<uint8_t> session_s_iv = { 0x1b, 0x13, 0xdd, 0x9f, 0x8d, 0x8f, 0x17, 0x09, 0x1d, 0x34, 0xb3, 0x49 };
  CHECK(serverM.key == session_s_key);
  CHECK(serverM.iv == session_s_iv);
  CHECK(clientM.key == session_c_key);
  CHECK(clientM.iv == session_c_iv);
}

TEST_CASE("hkdf finished calculation (Client)", "[HKDF]") {
  std::vector<uint8_t> messages = {
    0x01, 0x00, 0x00, 0xc6, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0x01, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 ,
    0x02, 0x00, 0x00, 0x76, 0x03, 0x03, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10, 0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 ,
     0x08, 0x00, 0x00, 0x02, 0x00, 0x00 ,
     0x0b, 0x00, 0x03, 0x2e, 0x00, 0x00, 0x03, 0x2a, 0x00, 0x03, 0x25, 0x30, 0x82, 0x03, 0x21, 0x30, 0x82, 0x02, 0x09, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x15, 0x5a, 0x92, 0xad, 0xc2, 0x04, 0x8f, 0x90, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x22, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x38, 0x31, 0x30, 0x30, 0x35, 0x30, 0x31, 0x33, 0x38, 0x31, 0x37, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x31, 0x30, 0x30, 0x35, 0x30, 0x31, 0x33, 0x38, 0x31, 0x37, 0x5a, 0x30, 0x2b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc4, 0x80, 0x36, 0x06, 0xba, 0xe7, 0x47, 0x6b, 0x08, 0x94, 0x04, 0xec, 0xa7, 0xb6, 0x91, 0x04, 0x3f, 0xf7, 0x92, 0xbc, 0x19, 0xee, 0xfb, 0x7d, 0x74, 0xd7, 0xa8, 0x0d, 0x00, 0x1e, 0x7b, 0x4b, 0x3a, 0x4a, 0xe6, 0x0f, 0xe8, 0xc0, 0x71, 0xfc, 0x73, 0xe7, 0x02, 0x4c, 0x0d, 0xbc, 0xf4, 0xbd, 0xd1, 0x1d, 0x39, 0x6b, 0xba, 0x70, 0x46, 0x4a, 0x13, 0xe9, 0x4a, 0xf8, 0x3d, 0xf3, 0xe1, 0x09, 0x59, 0x54, 0x7b, 0xc9, 0x55, 0xfb, 0x41, 0x2d, 0xa3, 0x76, 0x52, 0x11, 0xe1, 0xf3, 0xdc, 0x77, 0x6c, 0xaa, 0x53, 0x37, 0x6e, 0xca, 0x3a, 0xec, 0xbe, 0xc3, 0xaa, 0xb7, 0x3b, 0x31, 0xd5, 0x6c, 0xb6, 0x52, 0x9c, 0x80, 0x98, 0xbc, 0xc9, 0xe0, 0x28, 0x18, 0xe2, 0x0b, 0xf7, 0xf8, 0xa0, 0x3a, 0xfd, 0x17, 0x04, 0x50, 0x9e, 0xce, 0x79, 0xbd, 0x9f, 0x39, 0xf1, 0xea, 0x69, 0xec, 0x47, 0x97, 0x2e, 0x83, 0x0f, 0xb5, 0xca, 0x95, 0xde, 0x95, 0xa1, 0xe6, 0x04, 0x22, 0xd5, 0xee, 0xbe, 0x52, 0x79, 0x54, 0xa1, 0xe7, 0xbf, 0x8a, 0x86, 0xf6, 0x46, 0x6d, 0x0d, 0x9f, 0x16, 0x95, 0x1a, 0x4c, 0xf7, 0xa0, 0x46, 0x92, 0x59, 0x5c, 0x13, 0x52, 0xf2, 0x54, 0x9e, 0x5a, 0xfb, 0x4e, 0xbf, 0xd7, 0x7a, 0x37, 0x95, 0x01, 0x44, 0xe4, 0xc0, 0x26, 0x87, 0x4c, 0x65, 0x3e, 0x40, 0x7d, 0x7d, 0x23, 0x07, 0x44, 0x01, 0xf4, 0x84, 0xff, 0xd0, 0x8f, 0x7a, 0x1f, 0xa0, 0x52, 0x10, 0xd1, 0xf4, 0xf0, 0xd5, 0xce, 0x79, 0x70, 0x29, 0x32, 0xe2, 0xca, 0xbe, 0x70, 0x1f, 0xdf, 0xad, 0x6b, 0x4b, 0xb7, 0x11, 0x01, 0xf4, 0x4b, 0xad, 0x66, 0x6a, 0x11, 0x13, 0x0f, 0xe2, 0xee, 0x82, 0x9e, 0x4d, 0x02, 0x9d, 0xc9, 0x1c, 0xdd, 0x67, 0x16, 0xdb, 0xb9, 0x06, 0x18, 0x86, 0xed, 0xc1, 0xba, 0x94, 0x21, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x52, 0x30, 0x50, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x89, 0x4f, 0xde, 0x5b, 0xcc, 0x69, 0xe2, 0x52, 0xcf, 0x3e, 0xa3, 0x00, 0xdf, 0xb1, 0x97, 0xb8, 0x1d, 0xe1, 0xc1, 0x46, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x59, 0x16, 0x45, 0xa6, 0x9a, 0x2e, 0x37, 0x79, 0xe4, 0xf6, 0xdd, 0x27, 0x1a, 0xba, 0x1c, 0x0b, 0xfd, 0x6c, 0xd7, 0x55, 0x99, 0xb5, 0xe7, 0xc3, 0x6e, 0x53, 0x3e, 0xff, 0x36, 0x59, 0x08, 0x43, 0x24, 0xc9, 0xe7, 0xa5, 0x04, 0x07, 0x9d, 0x39, 0xe0, 0xd4, 0x29, 0x87, 0xff, 0xe3, 0xeb, 0xdd, 0x09, 0xc1, 0xcf, 0x1d, 0x91, 0x44, 0x55, 0x87, 0x0b, 0x57, 0x1d, 0xd1, 0x9b, 0xdf, 0x1d, 0x24, 0xf8, 0xbb, 0x9a, 0x11, 0xfe, 0x80, 0xfd, 0x59, 0x2b, 0xa0, 0x39, 0x8c, 0xde, 0x11, 0xe2, 0x65, 0x1e, 0x61, 0x8c, 0xe5, 0x98, 0xfa, 0x96, 0xe5, 0x37, 0x2e, 0xef, 0x3d, 0x24, 0x8a, 0xfd, 0xe1, 0x74, 0x63, 0xeb, 0xbf, 0xab, 0xb8, 0xe4, 0xd1, 0xab, 0x50, 0x2a, 0x54, 0xec, 0x00, 0x64, 0xe9, 0x2f, 0x78, 0x19, 0x66, 0x0d, 0x3f, 0x27, 0xcf, 0x20, 0x9e, 0x66, 0x7f, 0xce, 0x5a, 0xe2, 0xe4, 0xac, 0x99, 0xc7, 0xc9, 0x38, 0x18, 0xf8, 0xb2, 0x51, 0x07, 0x22, 0xdf, 0xed, 0x97, 0xf3, 0x2e, 0x3e, 0x93, 0x49, 0xd4, 0xc6, 0x6c, 0x9e, 0xa6, 0x39, 0x6d, 0x74, 0x44, 0x62, 0xa0, 0x6b, 0x42, 0xc6, 0xd5, 0xba, 0x68, 0x8e, 0xac, 0x3a, 0x01, 0x7b, 0xdd, 0xfc, 0x8e, 0x2c, 0xfc, 0xad, 0x27, 0xcb, 0x69, 0xd3, 0xcc, 0xdc, 0xa2, 0x80, 0x41, 0x44, 0x65, 0xd3, 0xae, 0x34, 0x8c, 0xe0, 0xf3, 0x4a, 0xb2, 0xfb, 0x9c, 0x61, 0x83, 0x71, 0x31, 0x2b, 0x19, 0x10, 0x41, 0x64, 0x1c, 0x23, 0x7f, 0x11, 0xa5, 0xd6, 0x5c, 0x84, 0x4f, 0x04, 0x04, 0x84, 0x99, 0x38, 0x71, 0x2b, 0x95, 0x9e, 0xd6, 0x85, 0xbc, 0x5c, 0x5d, 0xd6, 0x45, 0xed, 0x19, 0x90, 0x94, 0x73, 0x40, 0x29, 0x26, 0xdc, 0xb4, 0x0e, 0x34, 0x69, 0xa1, 0x59, 0x41, 0xe8, 0xe2, 0xcc, 0xa8, 0x4b, 0xb6, 0x08, 0x46, 0x36, 0xa0, 0x00, 0x00 ,
     0x0f, 0x00, 0x01, 0x04, 0x08, 0x04, 0x01, 0x00, 0x17, 0xfe, 0xb5, 0x33, 0xca, 0x6d, 0x00, 0x7d, 0x00, 0x58, 0x25, 0x79, 0x68, 0x42, 0x4b, 0xbc, 0x3a, 0xa6, 0x90, 0x9e, 0x9d, 0x49, 0x55, 0x75, 0x76, 0xa5, 0x20, 0xe0, 0x4a, 0x5e, 0xf0, 0x5f, 0x0e, 0x86, 0xd2, 0x4f, 0xf4, 0x3f, 0x8e, 0xb8, 0x61, 0xee, 0xf5, 0x95, 0x22, 0x8d, 0x70, 0x32, 0xaa, 0x36, 0x0f, 0x71, 0x4e, 0x66, 0x74, 0x13, 0x92, 0x6e, 0xf4, 0xf8, 0xb5, 0x80, 0x3b, 0x69, 0xe3, 0x55, 0x19, 0xe3, 0xb2, 0x3f, 0x43, 0x73, 0xdf, 0xac, 0x67, 0x87, 0x06, 0x6d, 0xcb, 0x47, 0x56, 0xb5, 0x45, 0x60, 0xe0, 0x88, 0x6e, 0x9b, 0x96, 0x2c, 0x4a, 0xd2, 0x8d, 0xab, 0x26, 0xba, 0xd1, 0xab, 0xc2, 0x59, 0x16, 0xb0, 0x9a, 0xf2, 0x86, 0x53, 0x7f, 0x68, 0x4f, 0x80, 0x8a, 0xef, 0xee, 0x73, 0x04, 0x6c, 0xb7, 0xdf, 0x0a, 0x84, 0xfb, 0xb5, 0x96, 0x7a, 0xca, 0x13, 0x1f, 0x4b, 0x1c, 0xf3, 0x89, 0x79, 0x94, 0x03, 0xa3, 0x0c, 0x02, 0xd2, 0x9c, 0xbd, 0xad, 0xb7, 0x25, 0x12, 0xdb, 0x9c, 0xec, 0x2e, 0x5e, 0x1d, 0x00, 0xe5, 0x0c, 0xaf, 0xcf, 0x6f, 0x21, 0x09, 0x1e, 0xbc, 0x4f, 0x25, 0x3c, 0x5e, 0xab, 0x01, 0xa6, 0x79, 0xba, 0xea, 0xbe, 0xed, 0xb9, 0xc9, 0x61, 0x8f, 0x66, 0x00, 0x6b, 0x82, 0x44, 0xd6, 0x62, 0x2a, 0xaa, 0x56, 0x88, 0x7c, 0xcf, 0xc6, 0x6a, 0x0f, 0x38, 0x51, 0xdf, 0xa1, 0x3a, 0x78, 0xcf, 0xf7, 0x99, 0x1e, 0x03, 0xcb, 0x2c, 0x3a, 0x0e, 0xd8, 0x7d, 0x73, 0x67, 0x36, 0x2e, 0xb7, 0x80, 0x5b, 0x00, 0xb2, 0x52, 0x4f, 0xf2, 0x98, 0xa4, 0xda, 0x48, 0x7c, 0xac, 0xde, 0xaf, 0x8a, 0x23, 0x36, 0xc5, 0x63, 0x1b, 0x3e, 0xfa, 0x93, 0x5b, 0xb4, 0x11, 0xe7, 0x53, 0xca, 0x13, 0xb0, 0x15, 0xfe, 0xc7, 0xe4, 0xa7, 0x30, 0xf1, 0x36, 0x9f, 0x9e ,

  };
  SHA256 hashObj(messages);
  std::vector<uint8_t> serverFinHash = hashObj;

  std::vector<uint8_t> sht_secret = { 0xa2, 0x06, 0x72, 0x65, 0xe7, 0xf0, 0x65, 0x2a, 0x92, 0x3d, 0x5d, 0x72, 0xab, 0x04, 0x67, 0xc4, 0x61, 0x32, 0xee, 0xb9, 0x68, 0xb6, 0xa3, 0x2d, 0x31, 0x1c, 0x80, 0x58, 0x68, 0x54, 0x88, 0x14 };
  auto s_fin_key = HKDF_Expand_Label<SHA256>(sht_secret, "finished", {}, 32);
  std::vector<uint8_t> shash = HMAC<SHA256>(serverFinHash, s_fin_key);
  std::vector<uint8_t> serverDigest = { 0xea, 0x6e, 0xe1, 0x76, 0xdc, 0xcc, 0x4a, 0xf1, 0x85, 0x9e, 0x9e, 0x4e, 0x93, 0xf7, 0x97, 0xea, 0xc9, 0xa7, 0x8c, 0xe4, 0x39, 0x30, 0x1e, 0x35, 0x27, 0x5a, 0xd4, 0x3f, 0x3c, 0xdd, 0xbd, 0xe3 };
  REQUIRE(serverDigest == shash);

  hashObj.add(std::vector<uint8_t>{ 0x14, 0x00, 0x00, 0x20 });
  hashObj.add(serverDigest);

  std::vector<uint8_t> cht_secret = { 0xff, 0x0e, 0x5b, 0x96, 0x52, 0x91, 0xc6, 0x08, 0xc1, 0xe8, 0xcd, 0x26, 0x7e, 0xef, 0xc0, 0xaf, 0xcc, 0x5e, 0x98, 0xa2, 0x78, 0x63, 0x73, 0xf0, 0xdb, 0x47, 0xb0, 0x47, 0x86, 0xd7, 0x2a, 0xea };
  std::vector<uint8_t> fin_hash = { 0x22, 0x84, 0x4b, 0x93, 0x0e, 0x5e, 0x0a, 0x59, 0xa0, 0x9d, 0x5a, 0xc3, 0x5f, 0xc0, 0x32, 0xfc, 0x91, 0x16, 0x3b, 0x19, 0x38, 0x74, 0xa2, 0x65, 0x23, 0x6e, 0x56, 0x80, 0x77, 0x37, 0x8d, 0x8b };
  std::vector<uint8_t> clientFinHash = hashObj;
  auto fin_key = HKDF_Expand_Label<SHA256>(cht_secret, "finished", {}, 32);
  std::vector<uint8_t> hash = HMAC<SHA256>(fin_hash, fin_key);
  std::vector<uint8_t> digest = { 0x97, 0x60, 0x17, 0xa7, 0x7a, 0xe4, 0x7f, 0x16, 0x58, 0xe2, 0x8f, 0x70, 0x85, 0xfe, 0x37, 0xd1, 0x49, 0xd1, 0xe9, 0xc9, 0x1f, 0x56, 0xe1, 0xae, 0xbb, 0xe0, 0xc6, 0xbb, 0x05, 0x4b, 0xd9, 0x2b };
  REQUIRE(fin_hash == clientFinHash);
  REQUIRE(hash == digest);
}



