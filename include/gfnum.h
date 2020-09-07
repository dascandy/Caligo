#include "bignum.h"

// R is implied the first bit over N size bignum
template <size_t W>
bignum<W> REDC(bignum<W> N, bignum<W> Nprime, bignum<2*W> T) {
    bignum<W> t = (T + (T.slice<W>(0) * Nprime).slice<W>(0) * N).slice<W>(W);
    auto [uf, v] = t - N;
    return (uf ? t : v);
}

template <size_t N>
bignum<N> exp_mod(bignum<N> value, bignum<N> exponent, bignum<N> polynomial) {
    // 1. convert all into montgomery form
    bignum<N> Nprime = 0; // TODO: how do we know?
    bignum<N> v = value;
    bignum<N> result = 0;
    // 2. constant-time exponentiate
    for (size_t i = 0; i < N*32; i++) {
        bignum<2*N> t = result * (exponent.bit(i) ? v : mont_one);
        result = REDC(polynomial, Nprime, t);
    }
    // 3. convert to normal form



    return result;
}


