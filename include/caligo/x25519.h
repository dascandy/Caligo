#pragma once

#include <cstdint>
#include <s2/span>
#include <s2/vector>
#include <s2/string>
#include "caligo/bignum.h"

struct ec_value {
  static constexpr bignum<8> modulus = { 0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF };
  static constexpr bignum<8> zero = { 0,0,0,0,0,0,0,0 };
  static constexpr uint32_t overflow_addition = 38;
  void wipe() {
    memset((char*)&v.v, 0, 32);
  }
  bignum<8> v;
  int bit(size_t n) const { return v.bit(n); }
  ec_value& operator=(uint32_t value) { v = value; return *this; }
  bool operator!=(const ec_value& rhs) { return !(v == rhs.v); }
  constexpr ec_value(std::initializer_list<uint32_t> nv) 
  : v(nv) {}
  constexpr ec_value(bignum<8> nv) 
  : v(nv) {}
  s2::vector<uint8_t> as_bytes() const { return v.as_bytes(); }
  friend ec_value operator+(const ec_value& a, const ec_value& b)
  {
    auto [overflow, value] = a.v + b.v;
    auto [ov2, v2] = value + bignum<8>(overflow * overflow_addition);
    bignum<8> v = v2;
    v.v[0] += ov2 * overflow_addition;
    return v;
  }
  friend ec_value operator*(const ec_value& a, uint32_t b)
  {
    bignum<9> x = a.v * b;
    uint64_t ov = (uint64_t)x[8] * 38;
    return ec_value(x.slice<8>(0)) + ec_value({uint32_t(ov & 0xFFFFFFFF), uint32_t(ov >> 32)});
  }
  friend ec_value operator*(const ec_value& a, const ec_value& b)
  {
    bignum<16> x = a.v * b.v;
    bignum<8> upper = x.slice<8>(8);
    bignum<8> lower = x.slice<8>(0);
    bignum<9> u38 = upper * 38;
    return ec_value(u38.slice<8>(0)) + ec_value(lower) + ec_value(u38.v[8] * 38);
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
    v[0] &= 0xfffffff8;
    v[7] |= 0x40000000;
    v[7] &= 0x7fffffff;
  }
  friend void ctime_swap(bool doswap, ec_value& a, ec_value& b) {
    ctime_swap(doswap, a.v, b.v);
  }
  // Fast method should be about 40% faster. Uses only 36 multiplications instead of 64
  ec_value square() const {
#ifndef FAST_SQUARE
    return *this * *this;
#else
    uint32_t x[16] = {};
    for (size_t i = 0; i < 8; i++) {
      uint64_t t = 0;
      for (size_t j = 0; j < i; j++) {
        t += (uint64_t)v[i] * v[j] * 2 + x[i+j];
        x[i+j] = (uint32_t)(t & 0xFFFFFFFF);
        t >>= 32;
      }
      t += (uint64_t)v[i] * v[i] + x[i+i];
      x[i+i] = (uint32_t)(t & 0xFFFFFFFF);
      t >>= 32;
      x[i+i+1] = (uint32_t)(t & 0xFFFFFFFF);
    }
    ec_value upper(s2::span<uint32_t>(x+8, x+16));
    ec_value lower(s2::span<uint32_t>(x, x+8));
    // add upper 38x to lower
    ec_value upper2 = upper + upper;
    ec_value upper4 = upper2 + upper2;
    ec_value upper8 = upper4 + upper4;
    ec_value upper16 = upper8 + upper8;
    ec_value upper32 = upper16 + upper16;
    ec_value upper38 = upper32 + upper4 + upper2;
    return lower + upper38;
#endif
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
  friend s2::string to_string(const ec_value& x) {
    char buffer[80];
    sprintf(buffer, "%08X %08X %08X %08X %08X %08X %08X %08X", x.v[0], x.v[1], x.v[2], x.v[3], x.v[4], x.v[5], x.v[6], x.v[7]);
    return buffer;
  }
  static ec_value random() {
    uint32_t values[] = {(uint32_t)rand(), (uint32_t)rand(), (uint32_t)rand(), (uint32_t)rand(), (uint32_t)rand(), (uint32_t)rand(), (uint32_t)rand(), (uint32_t)rand()};
    return bignum<8>{values};
  }
};

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
