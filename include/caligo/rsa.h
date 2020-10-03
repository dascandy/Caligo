#pragma once

#include <caligo/bignum.h>
#include <caligo/asn1.h>
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
#ifdef FAST
  return MontgomeryValue<N>(key.s, m).exp(key.e);
#else
  bignum<N> accum = 1;
  bignum<N> z = m;
  for (size_t x = 0; x < N; x++) {
    if (key.e.bit(x)) accum = (accum * z).naive_reduce(key.n);
    std::cout << "E " << to_string(accum) << "\n";
    z = (z * z).naive_reduce(key.n);
    std::cout << "E " << to_string(z) << "\n";
  }
  return accum;
#endif
}

template <size_t N = 2048>
bignum<N> rsadp(rsa_private_key<N> key, bignum<N> m) {
#ifdef FAST
  return MontgomeryValue<N>(key.s, m).exp(key.d);
#else
  bignum<N> accum = 1;
  bignum<N> z = m;
  for (size_t x = 0; x < N; x++) {
    if (key.d.bit(x)) accum = (accum * z).naive_reduce(key.n);
    std::cout << "D " << to_string(accum) << "\n";
    z = (z * z).naive_reduce(key.n);
    std::cout << "D " << to_string(z) << "\n";
  }
  return accum;
#endif
}

