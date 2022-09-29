#include "caligo/hash.h"
#include "caligo/md5.h"
#include "caligo/sha1.h"
#include "caligo/sha2.h"
#include "caligo/sha3.h"

namespace Caligo {

struct Hash::Impl {
  Impl(std::string_view hashName) {
    if (hashName == "md5") {
      impl.emplace<MD5>();
    } else if (hashName == "sha1" || hashName == "sha") {
      impl.emplace<SHA1>();
    } else if (hashName == "sha224" || hashName == "sha2-224") {
      impl.emplace<SHA2<224>>();
    } else if (hashName == "sha256" || hashName == "sha2-256") {
      impl.emplace<SHA2<256>>();
    } else if (hashName == "sha384" || hashName == "sha2-384") {
      impl.emplace<SHA2<384>>();
    } else if (hashName == "sha512" || hashName == "sha2-512") {
      impl.emplace<SHA2<512>>();
    } else if (hashName == "sha3-224") {
      impl.emplace<SHA3<224>>();
    } else if (hashName == "sha2-256") {
      impl.emplace<SHA3<256>>();
    } else if (hashName == "sha3-384") {
      impl.emplace<SHA3<384>>();
    } else if ("sha3-512") {
      impl.emplace<SHA3<512>>();
    } else {
      throw std::runtime_error("Invalid hash selected");
    }
  }
  size_t hashsize() {
    return std::visit([](auto& hash) { return hash.hashsize; }, impl);
  }
  void add(std::span<const uint8_t> data) {
    std::visit([&](auto& hash) { hash.add(data); }, impl);
  }
  operator std::vector<uint8_t>() const {
    return std::visit([](auto& hash) -> std::vector<uint8_t> { auto value = hash.data(); return std::vector<uint8_t>(value.begin(), value.end()); }, impl);
  }
  operator std::string() const {
    return std::visit([](auto& hash) -> std::string { return hash; }, impl);
  }
  size_t MaxLength() const {
    return std::visit([](auto& hash){ return hash.MaxLength(); }, impl);
  }
  std::vector<uint8_t> getAsn1Id() {
    return std::visit([](auto& hash) { return hash.getAsn1Id(); }, impl);
  }
private:
  std::variant<MD5, SHA1, SHA2<224>, SHA2<256>, SHA2<384>, SHA2<512>, SHA3<224>, SHA3<256>, SHA3<384>, SHA3<512>> impl;
};

Hash::Hash(std::string_view hashName) 
: impl(std::make_unique<Impl>(hashName))
{}

Hash::~Hash() = default;

size_t Hash::hashsize() {
  return impl->hashsize();
}

void Hash::add(std::span<const uint8_t> data) {
  impl->add(data);
}

Hash::operator std::vector<uint8_t>() const {
  return (*impl);
}

Hash::operator std::string() const {
  return (*impl);
}

size_t Hash::MaxLength() const {
  return impl->MaxLength();
}

std::vector<uint8_t> Hash::getAsn1Id() {
  return impl->getAsn1Id();
}

}


