#include <catch2/catch.hpp>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <caligo/gcm.h>
#include <caligo/aes.h>
#include <caligo/random_prime.h>

namespace Caligo {

static std::vector<uint8_t> fromHex(std::string str) {
  uint8_t hextab[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 
    0,10,11,12,13,14,15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0,10,11,12,13,14,15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  };
  std::vector<uint8_t> rv;
  rv.resize(str.size() / 2);
  for (size_t n = 0; n < rv.size() * 2; n += 2) {
    rv[n/2] = (hextab[(int)str[n]] << 4) | (hextab[(int)str[n+1]]);
  }
  return rv;
}

template <size_t bits>
static void test_aes(std::vector<uint8_t> key, std::vector<uint8_t> iv, std::vector<uint8_t> plaintext, std::vector<uint8_t> ciphertext, std::vector<uint8_t> aad, std::vector<uint8_t> tag_v, std::string expectedResult) {
  std::array<uint8_t, 16> tag;
  std::copy_n(tag_v.begin(), 16, tag.begin());
  auto [c_data, tag_data] = GCM<AES<bits>>({key, iv}).Encrypt(plaintext, aad);
  auto [p_data, is_valid] = GCM<AES<bits>>({key, iv}).Decrypt(ciphertext, aad, tag);
  if (expectedResult == "acceptable") {
    CHECK(c_data == ciphertext);
    CHECK(p_data == plaintext);
  } else if (expectedResult == "invalid") {
    CHECK(tag_data != tag);
    CHECK(not is_valid);
  } else if (expectedResult == "valid") {
    CHECK(c_data == ciphertext);
    CHECK(tag_data == tag);
    CHECK(p_data == plaintext);
    CHECK(is_valid);
  }
}
 
std::map<std::string, std::function<bool(nlohmann::json, nlohmann::json)>> testCaseHandler = {
  { "AES-GCM", [](nlohmann::json suite, nlohmann::json test) {
    if (suite["tagSize"] != 128) {
      return false;
    } else if (suite["keySize"] == 128) {
      test_aes<128>(fromHex(test["key"]), fromHex(test["iv"]), fromHex(test["msg"]), fromHex(test["ct"]), fromHex(test["aad"]), fromHex(test["tag"]), test["result"]);
      return true;
    } else if (suite["keySize"] == 256) {
      test_aes<256>(fromHex(test["key"]), fromHex(test["iv"]), fromHex(test["msg"]), fromHex(test["ct"]), fromHex(test["aad"]), fromHex(test["tag"]), test["result"]);
      return true;
    } else {
      return false;
    }
  } },
  { "PrimalityTest", [](nlohmann::json suite, nlohmann::json test) {
    (void)suite;
    auto value = fromHex(test["value"]);

    // big endian idiots
    std::reverse(value.begin(), value.end());
    bool isPrime;
    fprintf(stderr, "prim test %d: %s\n", int(test["tcId"]), std::string(test["comment"]).c_str());
    if (value.size() <= 32) {
      isPrime = Caligo::miller_rabin_is_probably_prime<256>(std::span<const uint8_t>(value));
    } else if (value.size() <= 128) {
      isPrime = Caligo::miller_rabin_is_probably_prime<1024>(std::span<const uint8_t>(value));
    } else {
      isPrime = Caligo::miller_rabin_is_probably_prime<3072>(std::span<const uint8_t>(value));
    }
    if (test["result"] == "valid") {
      CHECK(isPrime);
    } else if (test["result"] == "invalid") {
      CHECK(not isPrime);
    }
    fprintf(stderr, "prim test %d done\n", int(test["tcId"]));
    return true;
  }},
  { "ECDH", [](nlohmann::json suite, nlohmann::json test) { (void)suite; (void)test; return false; }},
  { "HKDF-SHA-1", [](nlohmann::json suite, nlohmann::json test) { (void)suite; (void)test; return false; }},
  { "HKDF-SHA-256", [](nlohmann::json suite, nlohmann::json test) { (void)suite; (void)test; return false; }},
  { "HKDF-SHA-384", [](nlohmann::json suite, nlohmann::json test) { (void)suite; (void)test; return false; }},
  { "HKDF-SHA-512", [](nlohmann::json suite, nlohmann::json test) { (void)suite; (void)test; return false; }},
  { "RSAES-PKCS1-v1_5", [](nlohmann::json suite, nlohmann::json test) { (void)suite; (void)test; return false; }},
  { "RSASSA-PKCS1-v1_5", [](nlohmann::json suite, nlohmann::json test) { (void)suite; (void)test; return false; }},
  { "RSASSA-PSS", [](nlohmann::json suite, nlohmann::json test) { (void)suite; (void)test; return false; }},
//  { "ECDSA", [](nlohmann::json suite, nlohmann::json test) { return false; }},
//  { "EDDSA", [](nlohmann::json suite, nlohmann::json test) { return false; }},
//  { "CHACHA20-POLY1305", [](nlohmann::json suite, nlohmann::json test) { return false; }},
};

/*
"AEAD-AES-SIV-CMAC", "AEGIS128", "AEGIS128L", "AEGIS256", "AES-CBC-PKCS5", "AES-CCM", "AES-CMAC", "AES-EAX", "AES-GCM",
"AES-GCM-SIV", "AES-GMAC", "AES-SIV-CMAC", "CHACHA20-POLY1305", "DSA", "ECDH", "ECDSA", "EDDSA", "HKDF-SHA-1",
"HKDF-SHA-256", "HKDF-SHA-384", "HKDF-SHA-512", "HMACSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA3-224", "HMACSHA3-256",
"HMACSHA3-384", "HMACSHA3-512", "HMACSHA384", "HMACSHA512", "KW", "KWP", "PrimalityTest", "RSAES-OAEP", 
"RSAES-PKCS1-v1_5", "RSASSA-PKCS1-v1_5", "RSASSA-PSS", "VMAC-AES", "XCHACHA20-POLY1305", "XDH",
*/

TEST_CASE("wycheproof test suites", "[wycheproof]") {
  std::map<std::string, size_t> testsSkipped;
  for (auto& entry : std::filesystem::directory_iterator("wycheproof/testvectors")) {
    if (not entry.is_regular_file()) continue;
    nlohmann::json j;
    try {
      std::string f;
      f.resize(entry.file_size());
      std::ifstream(entry.path()).read(f.data(), f.size());
      j = nlohmann::json::parse(f);
    } catch (std::exception& e) {
      printf("Found %s, does not parse because %s\n", entry.path().c_str(), e.what());
      continue;
    }

    auto handler = testCaseHandler.find(std::string(j["algorithm"]));
    if (handler == testCaseHandler.end()) {
      testsSkipped[j["algorithm"]] += int(j["numberOfTests"]);
    } else {
      for (auto& group : j["testGroups"]) {
        for (auto& test : group["tests"]) {
          if (not (handler->second)(group, test)) {
            testsSkipped[j["algorithm"]]++;
          }
        }
      }
    }
  }
  for (auto& [name, count] : testsSkipped) {
    printf("Skipped %zu tests for %s\n", count, name.c_str());
  }
}

}


