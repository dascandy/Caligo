#include <catch/catch.hpp>
#include <caligo/mont.h>

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
//  REQUIRE(ct == ct_test);
}

TEST_CASE("montgomery exponentiation", "[MONT]") {

}



