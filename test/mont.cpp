#include <catch/catch.hpp>
#include <caligo/mont.h>
#include <caligo/x25519.h>

bignum<8> polynomial = { 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFED };
MontgomeryState<8> s(polynomial);

TEST_CASE("Known montgomery state for x25519", "[MONT]") {
  bignum<8> N = { 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFED };
  bignum<8> Ninv = { 0x2F286BCA, 0x1AF286BC, 0xA1AF286B, 0xCA1AF286, 0xBCA1AF28, 0x6BCA1AF2, 0x86BCA1AF, 0x286BCA1B };
  bignum<8> R1MN = { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000026 };
  bignum<8> R2MN = { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x000005A4 };
  bignum<8> R3MN = { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x0000D658 };
  bignum<9> R = { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
  bignum<8> R1MN_new = R.naive_reduce(polynomial);
  CHECK(to_string(R1MN_new) == to_string(R1MN));
  CHECK(to_string(s.N) == to_string(N));
  CHECK(to_string(s.Ninv) == to_string(Ninv));
  CHECK(to_string(s.R2MN) == to_string(R2MN));
  CHECK(to_string(s.R3MN) == to_string(R3MN));
//  bignum<16> mix = s.N * s.Ninv;
//  CHECK(to_string(mix.slice<8>(0)) == to_string(bignum<8>(1)));
}

TEST_CASE("montgomery convert to and from", "[MONT]") {
  bignum<8> one_r = s.REDC(s.R1MN);
  REQUIRE(to_string(one_r) == to_string(bignum<8>(1)));

  MontgomeryValue<8> one(s, bignum<8>(1));
  bignum<8> one_BN = one;
  REQUIRE(to_string(one_BN) == to_string(bignum<8>(1)));
  MontgomeryValue<8> two(s, bignum<8>(2));
  MontgomeryValue<8> three = one + two;
  bignum<8> three_BN = three;
  REQUIRE(three_BN == bignum<8>(3));
}

TEST_CASE("montgomery single multiply", "[MONT]") {
  bignum<8> a = { 0x2a2cb91d, 0xa5fb77b1, 0x2a99c0eb, 0x872f4cdf, 0x4566b251, 0x72c1163c, 0x7da51873, 0x0a6d0777 };
  bignum<8> b = { 0xebe088ff, 0x278b2f1c, 0xfdb61826, 0x29b13b6f, 0xe60e8083, 0x8b7fe179, 0x4b8a4a62, 0x7e08ab5d };
  bignum<8> v = (a * b).naive_reduce(polynomial);
  ec_value ea = a;
  ec_value eb = b;
  ec_value ev = ea * eb;
  MontgomeryValue ma(s, a);
  MontgomeryValue mb(s, b);
  MontgomeryValue mv = ma * mb;
  bignum<8> v1 = mv;
  CHECK(ev.v == v);
  CHECK(v1 == v);
}

TEST_CASE("montgomery exponentiation is correct", "[MONT]") {
  bignum<8> a = { 0x2a2cb91d, 0xa5fb77b1, 0x2a99c0eb, 0x872f4cdf, 0x4566b251, 0x72c1163c, 0x7da51873, 0x0a6d0777 };
  bignum<8> b = { 0xebe088ff, 0x278b2f1c, 0xfdb61826, 0x29b13b6f, 0xe60e8083, 0x8b7fe179, 0x4b8a4a62, 0x7e08ab5d };
  MontgomeryValue ma(s, a);
  MontgomeryValue mb(s, b);
  bignum<8> one = 1;
  bignum<8> v = 1;
  MontgomeryValue<8> mone(s, 1);
  MontgomeryValue<8> mv(s, 1);
  for (size_t n = 0; n < 256; n++) {
    v = v * (a.bit(n) ? v : one);
    mv = mv * (a.bit(n) ? mv : mone);
  }
  bignum<8> mres = mv;
  CHECK(v == mres);
}
/*
TEST_CASE("Montgomery performance test", "[MONT]") {
  bignum<8> a = { 0x2a2cb91d, 0xa5fb77b1, 0x2a99c0eb, 0x872f4cdf, 0x4566b251, 0x72c1163c, 0x7da51873, 0x0a6d0777 };
  bignum<8> b = { 0xebe088ff, 0x278b2f1c, 0xfdb61826, 0x29b13b6f, 0xe60e8083, 0x8b7fe179, 0x4b8a4a62, 0x7e08ab5d };
  MontgomeryValue mb(s, b);
  bignum<8> one = 1;
  bignum<8> v = 1;
  bignum<8> total = 1;
  bignum<8> total2 = 1;
  MontgomeryValue<8> mone(s, 1);
  MontgomeryValue<8> mv(s, 1);
  auto t1 = std::chrono::system_clock::now();
  for (size_t k = 0; k < 10000; k++) {
    for (size_t n = 0; n < 256; n++) {
      v = v * (a.bit(n) ? v : one);
      b = b * b;
    }
    total = total * v;
  }
  auto t2 = std::chrono::system_clock::now();
  for (size_t k = 0; k < 10000; k++) {
    for (size_t n = 0; n < 256; n++) {
      mv = mv * (a.bit(n) ? mv : mone);
      mb = mb * mb;
    }
    total2 = total2 * (bignum<8>)mv;
  }
  auto t3 = std::chrono::system_clock::now();
  CHECK(total == total2);
  std::cout << "Speedup " << std::chrono::duration_cast<std::chrono::microseconds>(t3 - t2).count() << " vs " << std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() << "\n";
}
*/

