#include <catch2/catch.hpp>
#include <caligo/random_prime.h>
#include <map>
#include <vector>

namespace Caligo {

TEST_CASE("the most egregious failures from wycheproof", "[PRIME]") {
  CHECK(not miller_rabin_is_probably_prime(bignum<32>(255)));
  CHECK(not miller_rabin_is_probably_prime(bignum<32>(0)));
  CHECK(not miller_rabin_is_probably_prime(bignum<32>(1)));
  CHECK(not miller_rabin_is_probably_prime(bignum<32>(0x123a99)));
  CHECK(not miller_rabin_is_probably_prime(bignum<32>(0xbc18d1)));
  CHECK(not miller_rabin_is_probably_prime(bignum<32>(4)));
  CHECK(not miller_rabin_is_probably_prime(bignum<32>(9)));
  CHECK(not miller_rabin_is_probably_prime(bignum<32>(0x10201)));

  CHECK(miller_rabin_is_probably_prime(bignum<32>(2)));
  CHECK(miller_rabin_is_probably_prime(bignum<32>(3)));
  CHECK(miller_rabin_is_probably_prime(bignum<32>(5)));
  CHECK(miller_rabin_is_probably_prime(bignum<32>(97)));
  CHECK(miller_rabin_is_probably_prime(bignum<32>(101)));
  CHECK(miller_rabin_is_probably_prime(bignum<32>(251)));
  CHECK(miller_rabin_is_probably_prime(bignum<32>(257)));
}
/*
TEST_CASE("generate random tiny primes", "[PRIME]") {
  std::vector<bignum<32>> nums;
  for (size_t n = 0; n < 2000; n++) {
    bignum<32> p = random_prime<32>();
    nums.push_back(p);
  }
  for (size_t i = 0; i < nums.size(); i++) {
    for (size_t j = i; j < nums.size(); j++) {
      CHECK(not miller_rabin_is_probably_prime(nums[i] * nums[j]));
    }
  }
}

TEST_CASE("generate random medium primes", "[PRIME]") {
  std::vector<bignum<256>> nums;
  for (size_t n = 0; n < 200; n++) {
    bignum<256> p = random_prime<256>();
    nums.push_back(p);
  }
  for (size_t i = 0; i < nums.size(); i++) {
    for (size_t j = i; j < nums.size(); j++) {
      CHECK(not miller_rabin_is_probably_prime(nums[i] * nums[j]));
    }
  }
}

TEST_CASE("generate random large primes", "[PRIME]") {
  bignum<2048> p = random_prime<2048>();
  (void)p;
}
*/

}

