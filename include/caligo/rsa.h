#pragma once

#include "caligo/bignum.h"
#include "caligo/asn1.h"

template <size_t N = 2048>
struct rsa_public_key {
  bignum<N/32> n; // 2048 bit
  bignum<N/32> e; // 2048 bit
};

template <size_t N = 2048>
struct rsa_private_key : rsa_public_key {
  bignum<N/32> d; // 2048 bit
};

template <size_t N = 2048>
bignum<N/32> rsaep(rsa_public_key key, bigint<N/32> m) {

      1.  If the message representative m is not between 0 and n - 1,
          output "message representative out of range" and stop.
      2.  Let c = m^e mod n.
      3.  Output c.
}


template <size_t N = 2048>
bignum<N/32> rsadp(rsa_public_key key, bigint<N/32> message) {
   RSAEP ((n, e), m)
      1.  If the ciphertext representative c is not between 0 and n - 1,
          output "ciphertext representative out of range" and stop.
      2.  Let m = c^d mod n.
      3.  Output m.
}

