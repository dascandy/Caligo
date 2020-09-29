#include <cstddef>
#include <caligo/bignum.h>

template <size_t N>
inline auto RecursiveInverseModPower2(bignum<N> A) {
  if constexpr (N > 1) {
    bignum<N> r = RecursiveInverseModPower2(A.template slice<(N+1)/2>(0));
    bignum<N> rv = r * (2 - (r * A).template slice<N>(0)).second;
    return rv;
  } else {
    uint32_t r = A.v[0] % 4; // odd numbers below 4/8 are their own inverse modulo 4/8.

    for (size_t n = 0; n < 4; n++) { // each iteration doubles the number of accurate bits.
      r = r*(2-r*A.v[0]);            // 2->4->8->16->32, so 4 runs
    }

    return bignum<1>(r);
  }
}

template <size_t K>
struct MontgomeryState {
  bignum<K> N;
  bignum<K> Ninv;
  bignum<K> R1MN;
  bignum<K> R2MN;
  bignum<K> R3MN;
  MontgomeryState(bignum<K> N) 
  : N(N) 
  {
    Ninv = RecursiveInverseModPower2(N);
    Ninv.neg();
    Ninv = (Ninv + bignum<K>(1)).second;

    bignum<2*K+1> R;
    R.v[2*K] = 1;
    R2MN = R.naive_reduce(N);

    R1MN = REDC(R2MN);
    R3MN = REDC(R2MN * R2MN);
  }
  bignum<K> REDC(bignum<2*K> v) {
    bignum<K> m = (v.template slice<K>(0) * Ninv).template slice<K>(0);
    bignum<K> t = (v + m * N).second.template slice<K>(K);
    auto [carry, t2] = t - N;
    return carry ? t : t2;
  }
};


template <size_t K>
struct MontgomeryValue {
  MontgomeryState<K>& state;
  bignum<K> value;
  MontgomeryValue(MontgomeryState<K>& state, const bignum<K>& in) 
  : state(state)
  {
    value = state.REDC(in * state.R2MN);
  }
  /*
  MontgomeryValue inverse() const {
   //The modular inverse of aR mod N is REDC((aR mod N)−1(R3 mod N)).
   // How to get (aR mod N) ^ -1 ?
   bignum<K> invvalue = value;
   return state.REDC(invvalue * state.R3MN);
  }
  */
  MontgomeryValue operator+(const MontgomeryValue& rhs) const {
    MontgomeryValue rv(state, 0);
    for (size_t n = 0; n < K; n++) {
      uint64_t v = value[n] + rhs.value[n];
      rv.value[n] = (uint32_t)v;
      v >>= 32;
    }
    return rv;
  }
  MontgomeryValue operator*(const MontgomeryValue& rhs) const {
    return state.REDC(rhs.value * value);
  }
  operator bignum<K>() {
    return state.REDC(value);
  }
};

