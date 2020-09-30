#pragma once

#include <caligo/bignum.h>
#include <caligo/asn1.h>
#include <caligo/mont.h>

template <size_t N = 2048>
struct rsa_public_key {
  MontgomeryState<N/32> s;
  bignum<N/32> e;
  rsa_public_key(bignum<N/32> n, bignum<N/32> e)
  : s(n)
  , e(e)
  {}
};

template <size_t N = 2048>
struct rsa_private_key : rsa_public_key<N> {
  bignum<N/32> d; // 2048 bit
  rsa_private_key(bignum<N/32> n, bignum<N/32> e, bignum<N/32> d)
  : rsa_public_key<N>(n, e)
  , d(d)
  {}
};

template <size_t N = 2048>
bignum<N/32> rsaep(rsa_public_key<N> key, bignum<N/32> m) {
  return MontgomeryValue<N/32>(key.s, m).exp(key.e);
}


template <size_t N = 2048>
bignum<N/32> rsadp(rsa_private_key<N> key, bignum<N/32> m) {
  return MontgomeryValue<N/32>(key.s, m).exp(key.d);
}

