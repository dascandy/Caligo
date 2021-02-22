#pragma once

#include <caligo/bignum.h>
#include <caligo/mont.h>
#include <caligo/sha1.h>
#include <caligo/pkcs1.h>
#include <caligo/random.h>

#include <span>
#include <array>
#include <vector>
#include <cstdint>
#include <cstdio>

namespace Caligo {

// RFC8017, chapter B.2.1: MGF1
//      Hash     hash function (hLen denotes the length in octets of
//               the hash function output)
template <typename Hash = SHA1>
struct MGF1 {
  static constexpr size_t hashsize = Hash::hashsize;
  static std::vector<uint8_t> MGF(std::span<const uint8_t> seed, size_t length) {
    // 1.  If maskLen > 2^32 hLen, output "mask too long" and stop.
    if (length > 0x100000000ULL) return {};

    // 2.  Let T be the empty octet string.
    std::vector<uint8_t> T;

    std::vector<uint8_t> C(seed.begin(), seed.end());
    C.resize(C.size() + 4);
    while (T.size() < length) {
      //  3B.  (repeatedly, while incrementing C) Concatenate the hash of the seed mgfSeed and C to the octet string T:
      //         T = T || Hash(mgfSeed || C) .
      std::vector<uint8_t> hv = Hash(C);
      T.insert(T.end(), hv.begin(), hv.end());
      C[C.size() - 1]++;
      if (C[C.size() - 1] == 0) {
        C[C.size() - 2]++;
        if (C[C.size() - 2] == 0) {
          C[C.size() - 3]++;
          if (C[C.size() - 3] == 0) {
            C[C.size() - 4]++;
          }
        }
      }
    }

    // 4.  Output the leading maskLen octets of T as the octet string mask.
    T.resize(length);
    return T;
  }
};

template <typename Hash, size_t sLen>
std::vector<uint8_t> getSalt(std::span<const uint8_t> sig) {
  std::span<const uint8_t> H(sig.data() + sig.size() - Hash::hashsize - 1, sig.data() + sig.size() - 1);
  std::vector<uint8_t> dbmask = MGF1<Hash>::MGF(H, sig.size() - Hash::hashsize - 1);
  std::vector<uint8_t> salt;
  for (size_t n = dbmask.size() - sLen; n < dbmask.size(); n++) 
  {
    salt.push_back(sig[n] xor dbmask[n]);
  }
  return salt;
}

template <typename Hash>
std::vector<uint8_t> generatePssData(std::span<const uint8_t> data, std::span<const uint8_t> salt, size_t desiredLength) {
  Hash Hh;
  Hh.add(std::vector<uint8_t>({0,0,0,0,0,0,0,0}));
  Hh.add(data);
  Hh.add(salt);
  std::vector<uint8_t> H = Hh;
  std::vector<uint8_t> dbmask = MGF1<Hash>::MGF(H, desiredLength - Hash::hashsize - 1);
  dbmask[dbmask.size() - salt.size() - 1] ^= 0x01;
  for (size_t n = 0; n < salt.size(); n++) {
    dbmask[dbmask.size() - salt.size() + n] ^= salt[n];
  }
  dbmask.insert(dbmask.end(), H.begin(), H.end());
  dbmask.push_back(0xbc);
  return dbmask;
}

}

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

  std::array<uint8_t, 9> RsaSHA256 = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};
  std::array<uint8_t, 9> RsaSHA384 = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c};
  std::array<uint8_t, 9> RsaSHA512 = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d};

  bignum<N> rsaep(bignum<N> m) const {
    if (e == bignum<N>(65537)) {
      bignum<N> z = m;
      for (size_t x = 0; x < 16; x++) {
        z = (z * z).naive_reduce(n);
      }
      return (z * m).naive_reduce(n);
    } else {
      return MontgomeryValue<N>(s, m).exp(e);
    }
  }
  template <typename Hash>
  bool validatePkcs1_5Signature(std::span<const uint8_t> data, std::span<const uint8_t> sig) const {
    std::vector<uint8_t> hash = Caligo::PKCS1<Hash>(data, sig.size());
    std::reverse(hash.begin(), hash.end());
    return bignum<N>(hash) == rsaep(bignum<N>(sig));
  }
  template <typename Hash, typename MGF>
  bool validatePssSignature(std::span<const uint8_t> message, std::span<const uint8_t> sig) const {
    std::vector<uint8_t> sigR(sig.begin(), sig.end());
    std::reverse(sigR.begin(), sigR.end());
    bignum<N> sigBN = bignum<N>(sigR);
    std::vector<uint8_t> dSigV = rsaep(sigBN).as_bytes();
    dSigV.resize(sig.size());
    std::reverse(dSigV.begin(), dSigV.end());
    std::vector<uint8_t> salt = Caligo::getSalt<Hash, MGF::hashsize>(dSigV);
    std::vector<uint8_t> hMessage = Hash(message);
    std::vector<uint8_t> pssdata = Caligo::generatePssData<Hash>(hMessage, salt, dSigV.size());
    pssdata[0] &= 0x7F;
    return dSigV == pssdata;
  }
};

template <size_t N = 2048>
struct rsa_private_key {
  MontgomeryState<N> s;
  bignum<N> n;
  bignum<N> d;
  size_t actualN = N - 1;
  rsa_private_key(bignum<N> n, bignum<N> d)
  : s(n)
  , n(n)
  , d(d)
  {
    while (not n.bit(actualN)) actualN--;
    actualN++;
  }
  bignum<N> rsadp(bignum<N> m) const {
    return MontgomeryValue<N>(s, m).exp(d);
  }
  template <typename Hash>
  std::vector<uint8_t> signPkcs1_5Signature(std::span<const uint8_t> data) const {
    std::vector<uint8_t> hash = Caligo::PKCS1<Hash>(data, actualN / 8);
    std::reverse(hash.begin(), hash.end());
    std::vector<uint8_t> signature = rsadp(bignum<N>(hash)).as_bytes();
    while (signature[signature.size() - 1] == 0 && (signature[signature.size() - 2] & 0x80) == 0x00) signature.pop_back();
    std::reverse(signature.begin(), signature.end());
    return signature;
  }
  template <typename Hash, typename MGF>
  std::vector<uint8_t> signPssSignature(std::span<const uint8_t> message) const {
    std::vector<uint8_t> salt;
    salt.resize(MGF::hashsize);
#if 1
    generate_random(salt);
#else
    salt = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
#endif
    std::vector<uint8_t> pssData = Caligo::generatePssData<Hash>(message, salt, actualN / 8);
    pssData[0] &= 0x7F;
    std::reverse(pssData.begin(), pssData.end());
    std::vector<uint8_t> signature = rsadp(bignum<N>(pssData)).as_bytes();
    while (signature[signature.size() - 1] == 0 && (signature[signature.size() - 2] & 0x80) == 0x00) signature.pop_back();
    std::reverse(signature.begin(), signature.end());
    return signature;
  }
};


