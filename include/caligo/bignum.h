#pragma once

#include <cstdint>
#include <span>
#include <vector>
#include <string>
#include <iostream>

template <size_t N>
struct bignum {
  uint32_t v[N];
  constexpr const uint32_t& operator[](size_t index) const {
    return v[index];
  }
  constexpr uint32_t& operator[](size_t index) {
    return v[index];
  }
  constexpr int bit(size_t n) const {
    return (v[n / 32] >> (n % 32)) & 1;
  }
  constexpr bignum& operator=(uint32_t value) {
      memset(v, 0, sizeof(v));
      v[0] = value;
      return *this;
  }
  constexpr bignum(uint32_t value = 0) 
  : v{}
  {
      memset(v, 0, sizeof(v));
      v[0] = value;
  }
  constexpr bignum(std::initializer_list<uint32_t> list) 
  : v{}
  {
    size_t n = 0;
    for (auto i : list) {
      v[list.size() - n++ - 1] = i;
    }
  }
  constexpr bignum(std::span<const uint32_t> data) 
  : v{}
  {
    for (size_t i = 0; i < N; i++) {
      v[N - i - 1] = data[i];
    }
  }
  constexpr bignum(std::span<const uint8_t> data) 
  : v{}
  {
      for (size_t i = 0; i < N; i++) {
          v[i] = (data[i*4+0]) + (data[i*4+1] << 8) + (data[i*4+2] << 16) + (data[i*4+3] << 24);
      }
  }
  template <size_t K>
  constexpr bignum(const bignum<K>& value) 
  : v{}
  {
      for (size_t n = 0; n < std::min(K, N); n++) {
          v[n] = value.v[n];
      }
  }
  constexpr void shl_word(size_t words) {
      for (size_t n = 0; n < N-words; n++) {
          v[N - n - 1] = v[N - n - words - 1];
      }
      for (size_t n = N-words; n < N; n++) {
          v[N - n - 1] = 0;
      }
  }
  constexpr void shr1() {
    uint32_t bit = 0;
    for (size_t n = 0; n < N; n++) {
      uint32_t nb = v[N-1-n] << 31;
      v[N-1-n] = (v[N-1-n] >> 1) | bit;
      bit = nb;
    }
  }
  template <size_t K>
  constexpr bignum<K> naive_reduce(bignum<K>& p) {
    bignum<N> s = p;
    bignum<N> c = *this;
    s.shl_word(N-K);
    for (size_t n = N * 32; n > K * 32; n--) {
      s.shr1();
      auto [overflow, c2] = c - s;
      c = (overflow ? c : c2);
    }
    return c;
  }
  template <size_t K>
  constexpr bignum<K> slice(size_t start) {
    bignum<K> rv;
    for (size_t n = 0; n < K; n++) {
      rv.v[n] = v[n+start];
    }
    return rv;
  }
  std::vector<uint8_t> as_bytes() const {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < N; i++) {
      bytes.push_back(v[i] & 0xFF);
      bytes.push_back((v[i] >> 8) & 0xFF);
      bytes.push_back((v[i] >> 16) & 0xFF);
      bytes.push_back((v[i] >> 24) & 0xFF);
    }
    return bytes;
  }
  void neg() {
    for (auto& e : v) {
      e ^= 0xFFFFFFFF;
    }
  }
  friend constexpr bignum operator^(const bignum& a, const bignum& b)
  {
    bignum v;
    for (size_t index = 0; index < N; index++) {
      v.v[index] = a.v[index] ^ b.v[index];
    }
    return v;
  }
  constexpr bignum& operator^=(const bignum& a) {
    for (size_t index = 0; index < N; index++) {
      v[index] ^= a.v[index];
    }
    return *this;
  }
  constexpr bignum& operator&=(const bignum& a) {
    for (size_t index = 0; index < N; index++) {
      v[index] &= a.v[index];
    }
    return *this;
  }
  constexpr bool add(const uint32_t(& rhs)[N]) {
    uint64_t t = 0;
    for (size_t index = 0; index < N; index++) {
      t += (uint64_t)v[index] + rhs[index];
      v[index] = t & 0xffffffff;
      t >>= 32;
    }
    return t;
  }
  constexpr bool sub(const uint32_t(& rhs)[N]) {
    uint64_t t = 0;
    for (size_t index = 0; index < N; index++) {
      t = (uint64_t)v[index] - rhs[index] - (t ? 1 : 0);
      v[index] = t & 0xffffffff;
      t >>= 32;
    }
    return t;
  }
  friend constexpr std::pair<bool, bignum> operator+(const bignum& a, const bignum& b)
  {
    bignum v = a;
    bool overflow = v.add(b.v);
    return {overflow, v};
  }
  // Common enough operation
  friend constexpr bignum<N+1> operator*(const bignum& a, uint32_t b)
  {
    bignum<N+1> x;
    uint64_t t = 0;
    for (size_t i = 0; i < N; i++) {
      t += (uint64_t)a.v[i] * b;
      x.v[i] = (uint32_t)(t & 0xFFFFFFFF);
      t >>= 32;
    }
    x.v[N] = (uint32_t)(t & 0xFFFFFFFF);
    return x;
  }
  friend constexpr bignum<2*N> operator*(const bignum& a, const bignum& b)
  {
    bignum<2*N> x;
    for (size_t i = 0; i < N; i++) {
      uint64_t t = 0;
      for (size_t j = 0; j < N; j++) {
        t += (uint64_t)a.v[i] * b.v[j] + x.v[i+j];
        x.v[i+j] = (uint32_t)(t & 0xFFFFFFFF);
        t >>= 32;
      }
      x.v[i+N] = (uint32_t)(t & 0xFFFFFFFF);
    }
    return x;
  }
  bignum<2*N> square() const {
    // TODO: optimize this
    return *this * *this;
  }
  friend constexpr std::pair<bool, bignum> operator-(const bignum& a, const bignum& b)
  {
    bignum v = a;
    bool underflow = v.sub(b.v);
    return {underflow, v};
  }
  constexpr bool operator==(const bignum& rhs) const {
    uint32_t result = 0;
    for (size_t index = 0; index < N; index++) {
      result |= v[index] ^ rhs.v[index];
    }
    return result == 0;
  }
  constexpr bool operator<(const bignum& rhs) {
    return sub(rhs.v);
  }
  friend constexpr void ctime_swap(bool doswap, bignum& a, bignum& b) {
    bignum ones;
    for (size_t n = 0; n < N; n++) {
      ones[n] = 0xffffffff * doswap;
    }
    ones &= a ^ b;
    a ^= ones;
    b ^= ones;
  }
  friend std::string to_string(const bignum& x) {
    char buffer[10*N];
    buffer[0] = '\0';
    for (size_t n = 0; n < N; n++) {
      sprintf(buffer + strlen(buffer), "%08X ", x.v[N-n-1]);
    }
    buffer[strlen(buffer)-1] = 0;
    return buffer;
  }
};

template <size_t N>
std::ostream& operator<<(std::ostream& os, const bignum<N>& bn) {
  os << to_string(bn);
  return os;
}

