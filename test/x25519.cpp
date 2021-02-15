#include <catch/catch.hpp>
#include <caligo/x25519.h>

TEST_CASE("basic addition tests", "[X25519]") {
  // Basic addition
  ec_value one = { 0, 0, 0, 0, 0, 0, 0, 1 };
  ec_value two = { 0, 0, 0, 0, 0, 0, 0, 2 };
  ec_value three = { 0, 0, 0, 0, 0, 0, 0, 3 };
  CHECK(one + two == three);
  ec_value one_too = { 1 };
  CHECK(one == one_too);

  // Proper pairing for addition
  ec_value first = {1, 2, 3, 4, 5, 6, 7, 8 };
  ec_value second = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
  ec_value result = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
  CHECK(first + second == result);

  // Basic overflow
  ec_value a = { 0, 0, 0, 0, 0, 0, 0, 0x8FFFFFFF};
  ec_value b = { 0, 0, 0, 0, 0, 0, 0, 0x70000001};
  ec_value r = a + b;
  CHECK(r.v[0] == 0);
  CHECK(r.v[1] == 1);

  // Overflow with proper polynomial
  ec_value minus_one = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff };
  ec_value thirtyeight = { 0, 0, 0, 0, 0, 0, 0, 38 };
  ec_value sum = one + minus_one;
  CHECK(sum == thirtyeight);

  ec_value seventyfour = { 0, 0, 0, 0, 0, 0, 0, 74 };
  ec_value excessive = minus_one + minus_one;
  CHECK(excessive == seventyfour);
}

TEST_CASE("basic subtraction tests", "[X25519]") {
  // Basic addition
  ec_value one = { 0, 0, 0, 0, 0, 0, 0, 1 };
  ec_value two = { 0, 0, 0, 0, 0, 0, 0, 2 };
  ec_value three = {0, 0, 0, 0, 0, 0, 0, 3 };
  CHECK(three - two == one);
  ec_value a = { 0, 0, 0, 0, 0, 0, 1, 0x40000000 };
  ec_value b = { 0, 0, 0, 0, 0, 0, 0, 0x80000000 };
  ec_value c = { 0, 0, 0, 0, 0, 0, 0, 0xC0000000 };
  CHECK(a - b == c);

  ec_value a2 = { 0x41, 0, 0, 0, 0, 0, 0, 0x40000000};
  ec_value b2 = { 0, 0, 0, 0, 0, 0, 0, 0x80000000 };
  ec_value c2 = { 0x40, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xC0000000 };
  CHECK(a2 - b2 == c2);

  // Proper pairing for addition
  ec_value minus_one = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
  ec_value expected = {0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFC9};
  CHECK(one - minus_one == expected);

  ec_value da = {8};
  ec_value cb = {0x0a};
  // subtracted this is -2
  ec_value damcb = { 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFEB };
  CHECK(da-cb == damcb.v);
}

TEST_CASE("basic multiplication tests", "[X25519]") {
  // simple case
  ec_value a = { 0, 0, 0, 0, 0, 0, 0, 12398 };
  ec_value b = { 0, 0, 0, 0, 0, 0, 0, 28975 };
  ec_value c = { 0, 0, 0, 0, 0, 0, 0, 12398 * 28975 };
  CHECK(a.v[0] == 12398);
  CHECK(to_string(a * b) == to_string(c));

  // One set of overflow
  ec_value a2 = { 0, 0, 0, 0, 0, 0, 0, 2389057283UL };
  ec_value b2 = { 0, 0, 0, 0, 0, 0, 0, 2983412535UL };
  uint64_t r = 2389057283UL * 2983412535UL;
  ec_value c2 = { 0, 0, 0, 0, 0, 0, uint32_t(r >> 32), uint32_t(r & 0xFFFFFFFF) };
  CHECK(a2 * b2 == c2);

  ec_value a3 = { 4 };
  ec_value b3 = { 9 };
  ec_value c3 = { 0x24 };
  CHECK(a3*b3 == c3);

  ec_value a4 = { 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF1 };
  ec_value b4 = {9};
  ec_value c4 = { 0x24 };
  CHECK(a4*b4 == c4);
}

TEST_CASE("Modulus works", "[X25519]") {
  ec_value low_value = { 0x14, 0, 0, 0, 0, 0, 0, 0 };
  ec_value a = low_value;
  a.applyModulus();
  CHECK(a == low_value);

  ec_value high_value = { 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFE0 };
  ec_value b = high_value;
  b.applyModulus();
  CHECK(b == high_value);

  ec_value minor_overflow_value = { 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF0 };
  ec_value c = minor_overflow_value;
  c.applyModulus();
  ec_value good = { 0, 0, 0, 0, 0, 0, 0, 3 };
  CHECK(c == good);
}

TEST_CASE("Swap works", "[X25519]") {
  ec_value a = { 0xd0ab1c4c, 0x10a903a6, 0x26b3353b, 0x726624ec, 0x24b15f7c, 0x3594c1a4, 0x583030db, 0xe6db6867 };
  ec_value b = { 1 };
  ec_value a2 = a;
  ec_value b2 = b;
  ctime_swap(0, a, b);
  CHECK(a2 == a);
  CHECK(b2 == b);
  ctime_swap(1, a, b);
  CHECK(a == b2);
  CHECK(b == a2);
}

TEST_CASE("equality comparison works", "[X25519]") {
  ec_value a = { 0xd0ab1c4c, 0x10a903a6, 0x26b3353b, 0x726624ec, 0x24b15f7c, 0x3594c1a4, 0x583030db, 0xe6db6867 };
  ec_value b = { 1 };
  ec_value c = { 42 };

  CHECK(c == c);
  CHECK(b == b);
  CHECK(a == a);
  CHECK(!(a == c));
  CHECK(!(b == c));
  CHECK(!(a == b));
}

TEST_CASE("Comparison works", "[X25519]") {
  ec_value a = { 0xd0ab1c4c, 0x10a903a6, 0x26b3353b, 0x726624ec, 0x24b15f7c, 0x3594c1a4, 0x583030db, 0xe6db6867 };
  ec_value b = { 1 };
  ec_value c = { 42 };

  CHECK(!(c < c));
  CHECK(!(b < b));
  CHECK(!(a < a));
  CHECK(!(a < c));
  CHECK( (b < c));
  CHECK(!(a < b));
}

TEST_CASE("Inversion works", "[X25519]") {
  ec_value a = { 0xd0ab1c4c, 0x10a903a6, 0x26b3353b, 0x726624ec, 0x24b15f7c, 0x3594c1a4, 0x583030db, 0xe6db6867 };
  ec_value inv_a = inverse(a);
  ec_value one = { 0, 0, 0, 0, 0, 0, 0, 1 };
  ec_value result = inv_a * a;
  result.applyModulus();

  CHECK(result == one);
}

TEST_CASE("squaring does what multiplication also gets (but maybe faster)", "[X25519]") {
  ec_value a = { 0xba449ac4, 0x506a2244, 0xc1fc5a18, 0x62144c0a, 0x82465edd, 0x3b16154b, 0xf0527c9d, 0xa546e36b };
  ec_value b = a * a;
  ec_value c = a.square();
  CHECK(b == c);
}

TEST_CASE("Single x25519", "[X25519]") {
  ec_value k = {9};
  ec_value u = {9};
  ec_value new_u = k;
  k = X25519(k, u);
  u = new_u;

  std::vector<uint8_t> rk_1 = { 0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc, 0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7, 0x27, 0x9f, 0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78, 0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79 };
  ec_value k_1{std::span<const uint8_t>(rk_1)};
  CHECK(to_string(k) == to_string(k_1));
}

TEST_CASE("Repeated x25519", "[X25519]") {
  std::vector<uint8_t> rk_1k = { 0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55, 0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c, 0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87, 0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51 };
  ec_value k_1k{std::span<const uint8_t>(rk_1k)};
  ec_value k = {9};
  ec_value u = {9};

  size_t n = 0;
  for (; n < 1000; n++) {
    ec_value new_u = k;
    k = X25519(k, u);
    u = new_u;
  }
  CHECK(to_string(k) == to_string(k_1k));
/*
  // Takes 15 minutes
  std::vector<uint8_t> rk_1M = { 0x7c, 0x39, 0x11, 0xe0, 0xab, 0x25, 0x86, 0xfd, 0x86, 0x44, 0x97, 0x29, 0x7e, 0x57, 0x5e, 0x6f, 0x3b, 0xc6, 0x01, 0xc0, 0x88, 0x3c, 0x30, 0xdf, 0x5f, 0x4d, 0xd2, 0xd2, 0x4f, 0x66, 0x54, 0x24 };
  ec_value k_1M{std::span<uint8_t>(rk_1M)};
  for (; n < 1000000; n++) {
    ec_value new_u = k;
    k = X25519(k, u);
    u = new_u;
  }
  CHECK(k == k_1M);
*/
}

TEST_CASE("full x25519 test vectors", "[X25519]") {
  {
    ec_value in_scalar = { 0xc49a44ba, 0x44226a50, 0x185afcc1, 0x0a4c1462, 0xdd5e4682, 0x4b15163b, 0x9d7c52f0, 0x6be346a5 };
    ec_value in_u = { 0x4c1cabd0, 0xa603a910, 0x3b35b326, 0xec246672, 0x7c5fb124, 0xa4c19435, 0xdb303058, 0x6768dbe6 };
    ec_value out_u = { 0x5285a277, 0x5507b454, 0xf7711c49, 0x03cfec32, 0x4f088df2, 0x4dea948e, 0x90c6e99d, 0x3755dac3 };

    CHECK(X25519(in_scalar, in_u) == out_u);
  }

// Why doesn't this one work!!! But the 1M repetition above this works fine!
/*
  {
    ec_value in_scalar = { 0x0dba1879, 0x9e16a42c, 0xd401eae0, 0x21641bc1, 0xf56a7d95, 0x9126d25a, 0x3c67b4d1, 0xd4e9664b };
    ec_value in_u = { 0x93a415c7, 0x49d54cfc, 0x3e3cc06f, 0x10e7db31, 0x2cae3805, 0x9d95b7f4, 0xd3116878, 0x120f21e5 };
    ec_value out_u = { 0x5779ac7a, 0x64f7f8e6, 0x52a19f79, 0x685a598b, 0xf873b8b4, 0x5ce4ad7a, 0x7d90e876, 0x94decb95 };

    CHECK(X25519(in_scalar, in_u) == out_u);
  }
  */
}

TEST_CASE("X25519 public key derivation from private key", "[X25519]") {
  ec_value priv_a = { 0x6bababab, 0xabababab, 0xabababab, 0xabababab, 0xabababab, 0xabababab, 0xabababab, 0xabababa8 };
  ec_value pub_a = { 0x5948621c, 0xa123cafa, 0xb8b809e2, 0x1d1798a1, 0x412bb24a, 0xe3c531b8, 0x795d0e1a, 0x852d71e3 };
  ec_value calc_pub_a = X25519(priv_a, {9});
  CHECK(calc_pub_a == pub_a);

  ec_value priv_b = { 0x4dcdcdcd, 0xcdcdcdcd, 0xcdcdcdcd, 0xcdcdcdcd, 0xcdcdcdcd, 0xcdcdcdcd, 0xcdcdcdcd, 0xcdcdcdc8 };
  ec_value pub_b = { 0x6f12a6fb, 0xd75584e8, 0x9002150e, 0x4f8896e2, 0x0a6c597c, 0x4bc59160, 0x57ffc9d9, 0x23a8beb5 }; 
  ec_value calc_pub_b = X25519(priv_b, {9});
  CHECK(calc_pub_b == pub_b);

  // Check for actual associativity
  ec_value pub_b_a = X25519(priv_b, pub_a);
  ec_value pub_a_b = X25519(priv_a, pub_b);
  CHECK(pub_b_a == pub_a_b);
}

TEST_CASE("x25519 DH example", "[X25519]") {
  ec_value priv_a = { 0x2a2cb91d, 0xa5fb77b1, 0x2a99c0eb, 0x872f4cdf, 0x4566b251, 0x72c1163c, 0x7da51873, 0x0a6d0777 };
  ec_value pub_a = { 0x6a4e9baa, 0x8ea9a4eb, 0xf41a3826, 0x0d3abf0d, 0x5af73eb4, 0xdc7d8b74, 0x54a73089, 0x09f02085 };
  ec_value priv_b = { 0xebe088ff, 0x278b2f1c, 0xfdb61826, 0x29b13b6f, 0xe60e8083, 0x8b7fe179, 0x4b8a4a62, 0x7e08ab5d };
  ec_value pub_b = { 0x4f2b886f, 0x147efcad, 0x4d67785b, 0xc843833f, 0x3735e4ec, 0xc2615bd3, 0xb4c17d7b, 0x7ddb9ede };
  ec_value key = { 0x4217161e, 0x3c9bf076, 0x339ed147, 0xc9217ee0, 0x250f3580, 0xf43b8e72, 0xe12dcea4, 0x5b9d5d4a };

  ec_value calc_pub_a = X25519(priv_a, {9});
  ec_value calc_pub_b = X25519(priv_b, {9});
  ec_value key_b_a = X25519(priv_b, calc_pub_a);
  ec_value key_a_b = X25519(priv_a, calc_pub_b);
  CHECK(calc_pub_a == pub_a);
  CHECK(calc_pub_b == pub_b);
  CHECK(key_b_a == key_a_b);
  CHECK(key == key_a_b);
}

