#pragma once

namespace Caligo {

template <typename Hash>
std::vector<uint8_t> PKCS1(std::span<const uint8_t> data, size_t requestedSize) {
  std::vector<uint8_t> rv;
  rv.push_back(0);
  rv.push_back(1);
  while (rv.size() < requestedSize - Hash::getAsn1Id().size() - Hash::hashsize - 1) {
    rv.push_back(0xFF);
  }
  rv.push_back(0);
  std::vector<uint8_t> id = Hash::getAsn1Id();
  rv.insert(rv.end(), id.begin(), id.end());
  {
    std::vector<uint8_t> prefix;
    prefix.push_back({0x30});
    if (data.size() < 0x80) {
      prefix.push_back(data.size());
    } else if (data.size() < 0x100) {
      prefix.push_back(0x81);
      prefix.push_back(data.size());
    } else if (data.size() < 0x10000) {
      prefix.push_back(0x82);
      prefix.push_back((data.size() >> 8) & 0xFF);
      prefix.push_back(data.size() & 0xFF);
    } else {
      prefix.push_back(0x83);
      prefix.push_back((data.size() >> 16) & 0xFF);
      prefix.push_back((data.size() >> 8) & 0xFF);
      prefix.push_back(data.size() & 0xFF);
    }
    Hash hash;
    hash.add(prefix);
    hash.add(data);
    std::vector<uint8_t> hashBytes = hash;
    rv.insert(rv.end(), hashBytes.begin(), hashBytes.end());
  }
  return rv;
};

}


