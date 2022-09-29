#pragma once

#include "X509Certificate.h"

#include <map>
#include <optional>

namespace Caligo {

class Truststore {
public:
  static Truststore& Instance();
  std::optional<x509certificate*> get(const std::string& name);
  bool trust(std::vector<x509certificate> &untrustedCertificates, uint64_t currentTime);
  void addCertificate(x509certificate cert);
private:
  Truststore();
  std::map<std::string, x509certificate> trusted_certs;
};

}


