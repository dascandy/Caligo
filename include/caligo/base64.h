#pragma once

#include <string>
#include <span>
#include <string_view>
#include <vector>
#include <cstdint>

namespace Caligo {

enum Base64CharSet {
  PlusSlash = 0,
  PlusComma = 1,
  MinusUnderscore = 2,
  UrlSafe = 2,
};

std::string base64(std::span<const uint8_t> data, bool withNewlines = true, bool omitEqs = false, Base64CharSet charSet = PlusSlash);
std::vector<uint8_t> base64d(std::string_view str);

}


