#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include "caligo/key_iv_pair.h"

template <typename Hash>
std::vector<uint8_t> HMAC(std::vector<uint8_t> text, std::vector<uint8_t> key) {
  key.resize(Hash::hashsize*2);
  std::vector<uint8_t> o = key, i = key;
  for (auto& c : o) c ^= 0x5C;
  for (auto& c : i) c ^= 0x36;
  i.insert(i.end(), text.begin(), text.end());
  std::vector<uint8_t> h1 = Hash(i);
  o.insert(o.end(), h1.begin(), h1.end());
  return Hash(o);
}

template <typename Hash>
std::vector<uint8_t> HKDF_Extract(std::vector<uint8_t> salt, std::vector<uint8_t> ikm) {
  return HMAC<Hash>(ikm, salt);
}

template <typename Hash>
std::vector<uint8_t> HKDF_Expand(std::vector<uint8_t> prk, std::vector<uint8_t> info, size_t len) {
  std::vector<uint8_t> buffer;
  std::vector<uint8_t> lastT;
  size_t n = 1;
  while (buffer.size() < len) {
    lastT.insert(lastT.end(), info.begin(), info.end());
    lastT.push_back(n++);
    lastT = HMAC<Hash>(std::move(lastT), prk);
    buffer.insert(buffer.end(), lastT.begin(), lastT.end());
  }
  buffer.resize(len);
  return buffer;
}

template <typename Hash>
std::vector<uint8_t> HKDF_Expand_Label(std::vector<uint8_t> prk, std::string label, std::vector<uint8_t> context, size_t len) {
  std::vector<uint8_t> info;
  info.push_back((len >> 8) & 0xFF);
  info.push_back(len & 0xFF);
  std::string l = "tls13 " + label;
  info.push_back(l.size());
  info.insert(info.end(), l.begin(), l.end());
  info.push_back(context.size());
  info.insert(info.end(), context.begin(), context.end());
  return HKDF_Expand<Hash>(prk, info, len);
}

template <typename Hash>
struct secret {
  std::vector<uint8_t> data;
  template <typename Cipher>
  key_iv_pair<Cipher> get_key_iv(std::vector<uint8_t> hashSoFar, bool client, bool handshake = false) {
    const char* label = client ? (handshake ? "c hs traffic" : "c ap traffic") : (handshake ? "s hs traffic" : "s ap traffic");
    std::vector<uint8_t> traffic_secret = HKDF_Expand_Label<Hash>(data, label, hashSoFar, data.size());
    return {HKDF_Expand_Label<Hash>(traffic_secret, "key", {}, Cipher::keysize), HKDF_Expand_Label<Hash>(traffic_secret, "iv", {}, Cipher::ivsize)};
  }
  std::vector<uint8_t> get_finished_key(std::vector<uint8_t> hashSoFar, bool client) {
    const char* label = client ? "c hs traffic" : "s hs traffic";
    std::vector<uint8_t> traffic_secret = HKDF_Expand_Label<Hash>(data, label, hashSoFar, data.size());
    return HKDF_Expand_Label<Hash>(traffic_secret, "finished", {}, Hash::hashsize);
  }
};

template <typename Hash>
secret<Hash> HKDF_HandshakeSecret(std::vector<uint8_t> shared) {
  std::vector<uint8_t> nothing;
  nothing.resize(Hash::hashsize);
  return {HKDF_Extract<Hash>(HKDF_Expand_Label<Hash>(HKDF_Extract<Hash>(nothing, nothing), "derived", Hash(), Hash::hashsize), shared)};
}

template <typename Hash>
secret<Hash> HKDF_MasterSecret(secret<Hash> secret) {
  std::vector<uint8_t> nothing;
  nothing.resize(Hash::hashsize);
  return {HKDF_Extract<Hash>(HKDF_Expand_Label<Hash>(secret.data, "derived", Hash(), Hash::hashsize), nothing)};
}

template <typename Hash>
secret<Hash> HKDF_UpdateSecret(secret<Hash> secret) {
  return {HKDF_Expand_Label<Hash>(secret.data, "traffic upd", Hash(), Hash::hashsize)};
}

template <typename Hash>
std::vector<uint8_t> exporter_master(secret<Hash>& h, std::vector<uint8_t> hash) {
  return HKDF_Expand_Label(h.data, "exp master", hash, 32);
}

template <typename Hash>
std::vector<uint8_t> resumption_master(secret<Hash>& h, std::vector<uint8_t> hash) {
  return HKDF_Expand_Label(h.data, "res master", hash, 32);
}


