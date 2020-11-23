#include <cstddef>
#include <caligo/bignum.h>

template <size_t N>
inline auto RecursiveInverseModPower2(bignum<N> A) {
  if constexpr (bignum<N>::multiword) {
    bignum<N> r = RecursiveInverseModPower2(A.template slice<(N+1)/2>(0));
    bignum<N> rv = r * (2 - (r * A).template slice<N>(0)).second;
    return rv;
  } else {
    uint32_t r = A.v[0] % 4; // odd numbers below 4/8 are their own inverse modulo 4/8.

    for (size_t n = 0; n < 4; n++) { // each iteration doubles the number of accurate bits.
      r = r*(2-r*A.v[0]);            // 2->4->8->16->32, so 4 runs
    }

    return bignum<N>(r);
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
    R.set_bit(2*K);
    R2MN = R.naive_reduce(N);

    R1MN = REDC(R2MN);
    R3MN = REDC(R2MN * R2MN);
  }
  bignum<K> REDC(bignum<2*K> v) {
    bignum<K> m = (v.template slice<K>(0) * Ninv).template slice<K>(0);
    auto mn = m * N;
    auto vmn = v + mn;
    bignum<K> t = vmn.second.template slice<K>(K);
    auto [carry, t2] = t - N;
    return vmn.first ? t2 : t;
  }
};


template <size_t K>
struct MontgomeryValue {
  MontgomeryState<K>* state;
  bignum<K> value;
  MontgomeryValue(MontgomeryState<K>& state, const bignum<K>& in) 
  : state(&state)
  {
    value = state.REDC(in * state.R2MN);
  }
  MontgomeryValue operator+(const MontgomeryValue& rhs) const {
    MontgomeryValue rv(state);
    rv.value = (value + rhs.value).second;
    return rv;
  }
  MontgomeryValue operator*(const MontgomeryValue& rhs) const {
    MontgomeryValue rv(state);
    rv.value = state->REDC(rhs.value * value);
    return rv;
  }
  MontgomeryValue square() const {
    MontgomeryValue rv(state);
    rv.value = state->REDC(value.square());
    return rv;
  }
  MontgomeryValue exp(uint32_t exponent) const {
    (void)exponent;
    MontgomeryValue b = *this;
    MontgomeryValue<K> v(*state, 1);
    for (size_t n = 0; n < 16; n++) {
      b = b.square();
    }
    return b * *this;
  }
  MontgomeryValue exp(bignum<K> exponent) const {
    MontgomeryValue b = *this;
    MontgomeryValue<K> v(*state, 1);
    MontgomeryValue<K> one = v;
    for (size_t n = 0; n < K; n++) {
      v = v * (exponent.bit(n) ? b : one);
      b = b.square();
    }
    return v;
  }
  operator bignum<K>() const {
    return state->REDC(value);
  }
private:
  MontgomeryValue(MontgomeryState<K>* state)
  : state(state)
  {}
};

