#pragma once

#include <span>
#include <utility>
#include <cstdint>
#include <cstddef>

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
  cons = 160
};

struct asn1_view {
  std::span<uint8_t> data;
  size_t offset = 0;
  std::pair<asn1_id, std::span<uint8_t>> read() {
  
    asn1_id id = (asn1_id)data[offset++];
    size_t size = data[offset++];
    if (size & 0x80) {
      size_t bytes = size & 0x7F;
      size = 0;
      for (; bytes > 0; bytes--) {
        size = (size << 8) + data[offset];
      }
    }
    size_t off = offset;
    offset += size;
    return { id, std::span(data.data() + off, data.data() + off + size) };
  }
  bool atEnd() {
    return offset == data.size();
  }
};


