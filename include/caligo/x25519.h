#pragma once

#include <cstdint>
#include <span>
#include <vector>
#include <string>
#include "caligo/bignum.h"

namespace Caligo {

struct ec_value {
  static constexpr bignum<256> modulus = { 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFED };
  static constexpr bignum<256> zero = { 0,0,0,0,0,0,0,0 };
  static constexpr uint32_t overflow_addition = 38;
  void wipe() {
    memset((char*)&v.v, 0, 32);
  }
  bignum<256> v;
  int bit(size_t n) const { return v.bit(n); }
  ec_value& operator=(uint32_t value) { v = value; return *this; }
  bool operator!=(const ec_value& rhs) { return !(v == rhs.v); }
  constexpr ec_value(std::initializer_list<uint32_t> nv) 
  : v(nv) {}
  constexpr ec_value(bignum<256> nv) 
  : v(nv) {}
  std::vector<uint8_t> as_bytes() const { return v.as_bytes(); }
  friend ec_value operator+(const ec_value& a, const ec_value& b)
  {
    auto [overflow, value] = a.v + b.v;
    auto [ov2, v2] = value + bignum<256>(overflow * overflow_addition);
    bignum<256> v = v2;
    v.v[0] += ov2 * overflow_addition;
    return v;
  }
  friend ec_value operator*(const ec_value& a, uint32_t b)
  {
    bignum<288> x = a.v * b;
    uint64_t ov = (uint64_t)x[8] * 38; // TODO: find out how to do this non-32-bit assuming
    return ec_value(x.slice<256>(0)) + ec_value({uint32_t(ov >> 32), uint32_t(ov & 0xFFFFFFFF)});
  }
  friend ec_value operator*(const ec_value& a, const ec_value& b)
  {
    bignum<512> x = a.v * b.v;
    bignum<256> upper = x.slice<256>(256);
    bignum<256> lower = x.slice<256>(0);
    bignum<288> u38 = upper * 38;
    return ec_value(u38.slice<256>(0)) + ec_value(lower) + ec_value(u38.v[8] * 38);
  }
  friend ec_value operator-(const ec_value& a, const ec_value& b)
  {
    auto [uf, v] = a.v - b.v;
    auto [ov1, v2] = v + (uf ? modulus : zero);
    auto [ov2, v3] = v2 + (uf && !ov1 ? modulus : zero);
    return (v3 + ((uf && !ov1 && !ov2) ? modulus : zero)).second;
  }
  bool operator==(const ec_value& rhs) const {
    ec_value nl = *this;
    ec_value nr = rhs;
    nl.applyModulus();
    nr.applyModulus();
    return nl.v == nr.v;
  }
  bool operator<(const ec_value& rhs) const {
    ec_value nl = *this;
    ec_value nr = rhs;
    nl.applyModulus();
    nr.applyModulus();
    return nl.v < nr.v;
  }
  // The default addition/subtraction etc. keep numbers within the bits (with proper modulus application). This actually reduces it to within the required modulus.
  void applyModulus()
  {
    auto [uf, nv] = v - modulus;
    auto [_, nv2] = nv + (uf ? modulus : zero);
    auto [uf2, nv3] = nv2 - modulus;
    auto [__, nv4] = nv3 + (uf2 ? modulus : zero);
    v = nv4;
  }
  void normalize() {
    // TODO: replace with bit-set and bit-clear
    v.clear_bit(0);
    v.clear_bit(1);
    v.clear_bit(2);
    v.set_bit(254);
    v.clear_bit(255);
  }
  friend void ctime_swap(bool doswap, ec_value& a, ec_value& b) {
    ctime_swap(doswap, a.v, b.v);
  }
  // Fast method should be about 40% faster. Uses only 36 multiplications instead of 64
  ec_value square() const {
    return *this * *this;
  }
  friend ec_value inverse(const ec_value& z)
  {
    ec_value z2 = z.square();
    ec_value z4 = z2.square();
    ec_value z8 = z4.square();
    ec_value z9 = z8 * z;
    ec_value z11 = z9 * z2;
    ec_value z31 = z11.square() * z9;
    ec_value z2_10_5 = z31.square().square().square().square().square();
    ec_value z2_10_0 = z2_10_5 * z31;
    ec_value z2_15_5 = z2_10_0.square().square().square().square().square();
    ec_value z2_15_0 = z2_15_5 * z31;
    ec_value z2_30_0 = z2_15_0.square().square().square().square().square().square().square().square().square().square().square().square().square().square().square() * z2_15_0;
    ec_value z2_60_0 = z2_30_0.square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square() * z2_30_0;
    ec_value z2_120_0 = z2_60_0.square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square() * z2_60_0;
    ec_value z2_240_0 = z2_120_0.square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square().square() * z2_120_0;
    return z2_240_0.square().square().square().square().square().square().square().square().square().square().square().square().square().square().square() * z2_15_5 * z11;
  }
  friend std::string to_string(const ec_value& x) {
    return to_string(x.v);
  }
  static ec_value random_private_key() {
    ec_value key{bignum<256>::random()};
    key.normalize();
    return key;
  }
};

inline std::ostream& operator<<(std::ostream& os, const ec_value& e) {
  os << e.v;
  return os;
}

inline ec_value X25519(ec_value k, ec_value u) {
   k.normalize();

   ec_value x_2 = {1};
   ec_value z_2 = {0};
   ec_value x_3 = u;
   ec_value z_3 = {1};
   bool swap = false;

   for (size_t t = 256; t --> 0;) {
       bool k_t = k.bit(t);
       swap ^= k_t;
       ctime_swap(swap, x_2, x_3);
       ctime_swap(swap, z_2, z_3);
       swap = k_t;
       ec_value A = x_2 + z_2;
       ec_value AA = A.square();
       ec_value B = x_2 - z_2;
       ec_value BB = B.square();
       ec_value E = AA - BB;
       ec_value C = x_3 + z_3;
       ec_value D = x_3 - z_3;
       ec_value DA = D * A;
       ec_value CB = C * B;
       x_3 = (DA + CB).square();
       z_3 = u * (DA - CB).square();
       x_2 = AA * BB;
       z_2 = E * (AA + E * 121665);
   }

   ctime_swap(swap, x_2, x_3);
   ctime_swap(swap, z_2, z_3);
   ec_value rv = x_2 * inverse(z_2);
   rv.applyModulus();
   return rv;
}

}

