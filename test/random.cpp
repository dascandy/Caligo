#include <catch2/catch_all.hpp>
#include <caligo/random.h>
#include <map>
#include <vector>

namespace Caligo {

TEST_CASE("Random values are not obviously wrong", "[RANDOM]") {
  // This case handles, for example, the Ryzen 2000 series bug where RDRAND always returned 0 after suspend/resume.
  std::map<uint64_t, int> values;
  for (size_t n = 0; n < 10; n++) {
    values[generate_random_value()]++;
  }
  for (auto& [value, count] : values) {
    REQUIRE(count == 1);
  }
}

TEST_CASE("API offers 4 variants to generate data into a vector", "[RANDOM]") {
  std::vector<uint8_t> d8;
  std::vector<uint16_t> d16;
  std::vector<uint32_t> d32;
  std::vector<uint64_t> d64;
  d8.resize(1048576);
  generate_random(d8);
  d16.resize(1048576);
  generate_random(d16);
  d32.resize(1048576);
  generate_random(d32);
  d64.resize(1048576);
  generate_random(d64);
}

}


