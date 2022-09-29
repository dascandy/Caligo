#include "caligo/Truststore.h"

#include <fstream>
#include <optional>

namespace Caligo {

Truststore& Truststore::Instance() {
  static Truststore store;
  return store;
}

Truststore::Truststore() {
  std::ifstream in("/etc/ssl/certs/ca-certificates.crt");
  std::vector<uint8_t> buffer;
  buffer.resize(std::filesystem::file_size("/etc/ssl/certs/ca-certificates.crt"));
  in.read((char*)buffer.data(), buffer.size());
  std::vector<x509certificate> certs = parseCertificatesPem(buffer);
  for (auto& cert : certs) {
    trusted_certs[cert.subject] = std::move(cert);
  }
}

std::optional<x509certificate*> Truststore::get(const std::string& name) {
  auto it = trusted_certs.find(name);
  if (it == trusted_certs.end()) return std::nullopt;
  return &it->second;
}

void Truststore::addCertificate(x509certificate cert) {
  trusted_certs[cert.subject] = std::move(cert);
}

// Check that the target certificate could be valid at the current time.
//   If not, return false already.
// while we cannot confirm the current certificate is valid:
//   find the first certificate where we *do not* trust a certificate with its name (to prevent tricks), and where we *do* trust a certificate with its issuer as name.
//     If no certificates match this, then return false.
//   Check the start to be *after* the issuer's start date, and the end date to be *before* the issuer's end date. If not, discard cert & continue
//   Check that the certificate is validly signed with its issuer's public key. If not, discard cert & continue
//   If this is the target cert, then return true.
//   Mark certificate as valid and continue to the next

bool Truststore::trust(std::vector<x509certificate> &untrustedCertificates, uint64_t currentTime) {
  std::map<std::string, x509certificate*> localCertMap;
  for (auto& [name, cert] : trusted_certs) {
    localCertMap[name] = &cert;
  }
  if (untrustedCertificates[0].validity_start > currentTime)
    return false;
  if (untrustedCertificates[0].validity_end < currentTime)
    return false;

  for (size_t n = 0; n < untrustedCertificates.size();) {
    if (localCertMap.find(untrustedCertificates[n].subject) != localCertMap.end() ||
        localCertMap.find(untrustedCertificates[n].issuer) == localCertMap.end()) {
      n++;
      continue;
    }

    x509certificate& issuer = *localCertMap.find(untrustedCertificates[n].issuer)->second;
    x509certificate& cert = untrustedCertificates[n];

    if (cert.verify(issuer)) {
      if (n == 0) {
        return true;
      }
      localCertMap[untrustedCertificates[n].subject] = &untrustedCertificates[n];
    } else {
      untrustedCertificates[n] = {};
    }

    n = 0;
  }
  return false;
}

}


