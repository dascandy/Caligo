#pragma once

#include <caligo/bignum.h>
#include <caligo/mont.h>
#include <span>
#include <array>
#include <vector>
#include <cstdint>
#include <caligo/sha1.h>
#include <caligo/pkcs1.h>

namespace Caligo {

// RFC8017, chapter B.2.1: MGF1
//      Hash     hash function (hLen denotes the length in octets of
//               the hash function output)
template <typename Hash = SHA1>
struct MGF1 {
  static constexpr size_t hashsize = Hash::hashsize;
  static std::vector<uint8_t> MGF(std::vector<uint8_t> seed, size_t length) {
    // 1.  If maskLen > 2^32 hLen, output "mask too long" and stop.
    if (length > 0x100000000ULL) return {};

    // 2.  Let T be the empty octet string.
    std::vector<uint8_t> T;

    std::vector<uint8_t> C = seed;
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

// RFC8017, chapter 9.1.2: EMSA-PSS-VERIFY
template <typename Hash, size_t sLen, typename MGF = MGF1<>>
bool EMSA_PSS_VERIFY(std::span<const uint8_t> data, std::span<const uint8_t> em) {
  // 1.   If the length of M is greater than the input limitation for the hash 
  // function output "inconsistent" and stop.
  if (data.size() > Hash::MaxLength()) { printf("%s:%d\n", __FILE__, __LINE__); return false; }

  // 2.   Let mHash = Hash(M), an octet string of length hLen.
  std::vector<uint8_t> mHash = Hash(data);

  // 3.   If emLen < hLen + sLen + 2, output "inconsistent" and stop.
  if (em.size() < Hash::hashsize + sLen + 2) { printf("%s:%d\n", __FILE__, __LINE__); return false; }

  // 4.   If the rightmost octet of EM does not have hexadecimal value 0xbc, output "inconsistent" and stop.
  if (em[em.size() - 1] != 0xbc) { printf("%s:%d\n", __FILE__, __LINE__); return false; }
 
  // 5.   Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and let H be the next hLen octets.
  std::vector<uint8_t> H;
  for (size_t n = em.size() - Hash::hashsize - 1; n < em.size() - 1; n++) {
    H.push_back(em[n]);
  }

  // 6.   If the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB are not 
  //             all equal to zero, output "inconsistent" and stop.
  // Only support power of 8, so this is always a nop I think

  // 7.   Let dbMask = MGF(H, emLen - hLen - 1).
  std::vector<uint8_t> dbmask = MGF1<Hash>::MGF(H, em.size() - Hash::hashsize - 1);

  // 8.   Let DB = maskedDB \xor dbMask.
  std::vector<uint8_t> db;
  for (size_t n = 0; n < em.size() - Hash::hashsize - 1; n++) 
  {
    db.push_back(em[n] xor dbmask[n]);
  }
  db[0] &= 0x7F;

  // 9.   Set the leftmost 8emLen - emBits bits of the leftmost octet in DB to zero.
  // Only support power of 8, so this is always a nop I think

  // 10.  If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero or if 
  // the octet at position emLen - hLen - sLen - 1 (the leftmost position is 
  // "position 1") does not have hexadecimal value 0x01, output "inconsistent" and 
  // stop.
  if (db[db.size() - sLen - 1] != 0x01) { printf("%s:%d\n", __FILE__, __LINE__); return false; }
  for (size_t n = 0; n < db.size() - 1 - sLen; n++)
  {
    if (db[n] != 0) { printf("%s:%d\n", __FILE__, __LINE__); return false; }
  }

  // 11.  Let salt be the last sLen octets of DB.
  // 12.  Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
  //      M' is an octet string of length 8 + hLen + sLen with eight
  //      initial zero octets.
  std::vector<uint8_t> Mprime;
  Mprime.resize(8);
  Mprime.insert(Mprime.end(), mHash.begin(), mHash.end());
  Mprime.insert(Mprime.end(), db.begin() + db.size() - sLen, db.end());

  // 13.  Let H' = Hash(M'), an octet string of length hLen.
  std::vector<uint8_t> Hprime = Hash(Mprime);

  // 14.  If H = H', output "consistent".  Otherwise, output "inconsistent".
  return Hprime == H;
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
  bool validatePkcs1_5Signature(std::span<const uint8_t> data, std::span<const uint8_t> signature) const {
    std::vector<uint8_t> hash = Caligo::PKCS1<Hash>(data, signature.size());
    std::reverse(hash.begin(), hash.end());
    return bignum<N>(hash) == rsaep(bignum<N>(signature));
  }
  template <typename Hash, typename MGF>
  bool validatePssSignature(std::span<const uint8_t> message, std::span<const uint8_t> sig) const {
    if (sig.size() > (N / 8)) return false;
    std::vector<uint8_t> nsig(sig.data(), sig.data() + sig.size());
    std::reverse(nsig.begin(), nsig.end());
    auto sig_bytes = rsaep(bignum<N>(nsig)).as_bytes();
    sig_bytes.resize(sig.size());
    std::reverse(sig_bytes.begin(), sig_bytes.end());

    return Caligo::EMSA_PSS_VERIFY<Hash, MGF::hashsize, MGF>(message, sig_bytes);
  }
};

template <size_t N = 2048>
struct rsa_private_key {
  MontgomeryState<N> s;
  bignum<N> n;
  bignum<N> d;
  rsa_private_key(bignum<N> n, bignum<N> d)
  : s(n)
  , n(n)
  , d(d)
  {}
  bignum<N> rsadp(bignum<N> m) {
    return MontgomeryValue<N>(s, m).exp(d);
  }
};
