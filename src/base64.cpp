#include <caligo/base64.h>

namespace Caligo {
// multiple entries for 62/63 to handle differing variants
// they do not conflict in the decoding
static constexpr int8_t valueOf[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, 63, 62, -1, 63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

const char* getLookupFor(Base64CharSet charSet) {
  switch(charSet) {
    case PlusSlash: return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    case PlusComma: return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
    case MinusUnderscore: return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  }
}

std::string base64(std::span<const uint8_t> data, bool withNewlines, bool omitEqs, Base64CharSet charSet) {
  const char* encodingOf = getLookupFor(charSet);
  std::string out;
  out.reserve((data.size() * 4) / 3 + 4);
  uint32_t value = 0;
  size_t count = 0;
  size_t blocksOnLine = 0;
  for (auto b : data) {
    value = (value << 8) | b;
    count++;
    if (count == 3) {
      out.push_back(encodingOf[(value >> 18) & 0x3F]);
      out.push_back(encodingOf[(value >> 12) & 0x3F]);
      out.push_back(encodingOf[(value >>  6) & 0x3F]);
      out.push_back(encodingOf[(value >>  0) & 0x3F]);
      count = 0;
      blocksOnLine++;
      if (blocksOnLine == 19) {
        if (withNewlines) {
          out.push_back('\n');
        }
        blocksOnLine = 0;
      }
    }
  }
  switch(count) {
  case 0:
    break;
  case 1:
    out.push_back(encodingOf[(value >> 2) & 0x3F]);
    out.push_back(encodingOf[(value << 4) & 0x3F]);
    if (not omitEqs) {
      out.push_back('=');
      out.push_back('=');
    }
    break;
  case 2:
    out.push_back(encodingOf[(value >> 10) & 0x3F]);
    out.push_back(encodingOf[(value >> 4) & 0x3F]);
    out.push_back(encodingOf[(value << 2) & 0x3F]);
    if (not omitEqs) {
      out.push_back('=');
    }
    break;
  }
  if (withNewlines) {
    out.push_back('\n');
  }
  return out;
}

std::vector<uint8_t> base64d(std::string_view str) {
  std::vector<uint8_t> out;
  uint32_t value = 0;
  size_t count = 0;
  for (auto v : str) {
    int8_t r = valueOf[(uint8_t)v];
    if (r == -1) continue;

    value = (value << 6) | (uint8_t)r;
    count++;
    if (count != 4) continue;

    out.push_back((value >> 16) & 0xFF);
    out.push_back((value >> 8) & 0xFF);
    out.push_back((value >> 0) & 0xFF);
    count = 0;
  }
  switch(count) {
  case 0:
  case 1: // 1 should never happen.
    break;
  case 2:
    out.push_back((value >> 4) & 0xFF);
    break;
  case 3:
    out.push_back((value >> 10) & 0xFF);
    out.push_back((value >> 2) & 0xFF);
    break;
  }
  return out;
}

}

