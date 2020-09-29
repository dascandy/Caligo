#include <catch/catch.hpp>
#include <caligo/bignum.h>

TEST_CASE("Bignum", "[BIGNUM]") {
  bignum<2> one = { 0x00, 0x80000001 };
  bignum<2> two = { 0x0, 0x80000002 };
  bignum<2> three = { 0x01, 0x00000003 };
  REQUIRE(one + two == std::pair<bool, bignum<2>>{ false, three });
}

TEST_CASE("Bignum overflow", "[BIGNUM]") {
  bignum<2> one = { 0x80000000, 0x80000001 };
  bignum<2> two = { 0x80000000, 0x80000002 };
  bignum<2> three = { 0x01, 0x00000003 };
  REQUIRE(one + two == std::pair<bool, bignum<2>>{ true, three });
}

TEST_CASE("Naive reduce", "[BIGNUM]") {
  bignum<8> p = { 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFED };
  bignum<9> r1 = {1, 0, 0, 0, 0, 0, 0, 0, 0};
  bignum<17> r2 = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  auto rr1 = r1.naive_reduce(p);
  auto rr12 = (rr1 * rr1).naive_reduce(p);
  auto rr2 = r2.naive_reduce(p);
  REQUIRE(rr2 == rr12);
}
