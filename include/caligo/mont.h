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
    std::cout << "V   " << v << "\n";
    bignum<K> m = (v.template slice<K>(0) * Ninv).template slice<K>(0);
    std::cout << "M   " << m << "\n";
    auto mn = m * N;
    std::cout << "MN  " << mn << "\n";
    auto vmn = v + mn;
    std::cout << vmn.first << " / " << vmn.second << "\n";
    bignum<K> t = vmn.second.template slice<K>(K);
    std::cout << "T   " << t << "\n";
    auto [carry, t2] = t - N;
    std::cout << "T2  " << t2 << "\n";
    return carry ? t : t2;
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
    bignum<K> v = (*this);
    bignum<K> rv2 = (v * v).naive_reduce(state->N);
    if (bignum<K>(rv) != rv2) {
      std::cout << "SOMETHING FAILED!\n";
      std::cout << bignum<K>(*this) << " -> " << bignum<K>(rv) << "\n";
      std::cout << bignum<K>(v) << " -> " << bignum<K>(rv2) << "\n";
    }
    return rv;
  }
  MontgomeryValue exp(bignum<K> exponent) const {
    MontgomeryValue b = *this;
    MontgomeryValue<K> v(*state, 1);
    MontgomeryValue<K> one = v;
    for (size_t n = 0; n < 32*K; n++) {
      v = v * (exponent.bit(n) ? b : one);
      std::cout << to_string(bignum<K>(v)) << "\n";
      b = b.square();
      std::cout << to_string(bignum<K>(b)) << "\n";
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

