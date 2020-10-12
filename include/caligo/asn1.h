#pragma once

#include <span>
#include <utility>
#include <cstdint>
#include <cstddef>

struct object_id {
  object_id(std::span<const uint8_t> s)
  : data(s.data(), s.size())
  {
  }
  friend bool operator==(std::span<const uint8_t> rhs, const object_id& id) {
    return id.data == rhs;
  }
  std::vector<uint8_t> data;
};

enum class asn1_id {
  boolean = 1,
  integer = 2,
  bit_string = 3,
  octet_string = 4,
  null = 5,
  object = 6,
  utf8string = 12,
  printablestring = 19,
  utctime = 23,
  sequence = 48,
  set = 49,
  array0 = 160,
  array1 = 161,
  array2 = 162,
  array3 = 163,
  array4 = 164
};

struct asn1_view {
  std::span<const uint8_t> data;
  size_t offset = 0;
  asn1_view(std::span<uint8_t> data) 
  : data(data)
  {}
  std::pair<asn1_id, std::span<uint8_t>> read() {
    asn1_id id = (asn1_id)data[offset++];
    size_t size = data[offset++];
    if (size & 0x80) {
      size_t bytes = size & 0x7F;
      size = 0;
      for (; bytes --> 0;) {
        size = (size << 8) + data[offset++];
      }
    }
    size_t off = offset;
    offset += size;
    return { id, std::span(data.data() + off, data.data() + off + size) };
  }
  bool empty() {
    return offset == data.size();
  }
};


