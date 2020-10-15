#pragma once

#include <string>
#include <span>
#include <string_view>
#include <vector>
#include <cstdint>

std::string base64(std::span<const uint8_t> data);
std::vector<uint8_t> base64d(std::string_view str);

