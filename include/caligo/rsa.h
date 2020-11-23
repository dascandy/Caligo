#pragma once

#include <caligo/bignum.h>
#include <caligo/mont.h>

template <size_t N = 2048>
struct rsa_public_key {
  MontgomeryState<N> s;
  bignum<N> n;
  bignum<N> e;
  rsa_public_key(bignum<N> n, bignum<N> e)
  : s(n)
  , n(n)
  , e(e)
  {}
};

template <size_t N = 2048>
struct rsa_private_key : rsa_public_key<N> {
  bignum<N> d; // 2048 bit
  rsa_private_key(bignum<N> n, bignum<N> e, bignum<N> d)
  : rsa_public_key<N>(n, e)
  , d(d)
  {}
};

template <size_t N = 2048>
bignum<N> rsaep(rsa_public_key<N> key, bignum<N> m) {
  if (key.e == bignum<N>(65537)) {
    bignum<N> z = m;
    for (size_t x = 0; x < 16; x++) {
      z = (z * z).naive_reduce(key.n);
    }
    return (z * m).naive_reduce(key.n);
  } else {
    return MontgomeryValue<N>(key.s, m).exp(key.e);
  }
}

template <size_t N = 2048>
bignum<N> rsadp(rsa_private_key<N> key, bignum<N> m) {
  return MontgomeryValue<N>(key.s, m).exp(key.d);
}

