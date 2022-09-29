#include "caligo/X509Certificate.h"

#include "caligo/Asn1.h"
#include "caligo/Truststore.h"

#include <caligo/bignum.h>
#include <caligo/base64.h>
#include <caligo/sha2.h>
#include <caligo/pkcs1.h>

#include <optional>

namespace Caligo {

object_id object_id::X509NameParts::CommonName = std::span<const uint8_t>{{ 0x55, 0x04, 0x03 }};
object_id object_id::X509NameParts::Surname = std::span<const uint8_t>{{ 0x55, 0x04, 0x04 }};
object_id object_id::X509NameParts::SerialNumber = std::span<const uint8_t>{{ 0x55, 0x04, 0x05 }};
object_id object_id::X509NameParts::Country = std::span<const uint8_t>{{ 0x55, 0x04, 0x06 }};
object_id object_id::X509NameParts::Locality = std::span<const uint8_t>{{ 0x55, 0x04, 0x07 }};
object_id object_id::X509NameParts::StateOrProvince = std::span<const uint8_t>{{ 0x55, 0x04, 0x08 }};
object_id object_id::X509NameParts::StreetAddress = std::span<const uint8_t>{{ 0x55, 0x04, 0x09 }};
object_id object_id::X509NameParts::Organization = std::span<const uint8_t>{{ 0x55, 0x04, 0x0a }};
object_id object_id::X509NameParts::OrganizationIdentifier = std::span<const uint8_t>{{ 0x55, 0x04, 0x61 }};
object_id object_id::X509NameParts::OrganizationalUnit = std::span<const uint8_t>{{ 0x55, 0x04, 0x0b }};
object_id object_id::X509NameParts::Title = std::span<const uint8_t>{{ 0x55, 0x04, 0x0c }};
object_id object_id::X509NameParts::GivenName = std::span<const uint8_t>{{ 0x55, 0x04, 0x2a }};
object_id object_id::X509NameParts::EmailAddress = std::span<const uint8_t>{{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01}};
//object_id object_id::UserID = std::span<const uint8_t>{{ 0x55, 0x04, 0x0f }};
//object_id object_id::DomainComponent = std::span<const uint8_t>{{ 0x55, 0x04, 0x0a }};

object_id object_id::PublicKey::RsaEncryption = std::span<const uint8_t>{{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 }};
object_id object_id::PublicKey::RsaSsaPss = std::span<const uint8_t>{{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a }};
object_id object_id::PublicKey::EcPublicKey = std::span<const uint8_t>{{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 }};
object_id object_id::PublicKey::X25519 = std::span<const uint8_t>{{ 0x2b, 0x65, 0x6e }};
object_id object_id::PublicKey::X448 = std::span<const uint8_t>{{ 0x2b, 0x65, 0x6f }};

object_id object_id::SignatureType::Ed25519 = std::span<const uint8_t>{{ 0x2b, 0x65, 0x70 }};
object_id object_id::SignatureType::Ed448 = std::span<const uint8_t>{{ 0x2b, 0x65, 0x71 }};

object_id object_id::SignatureType::EcdsaSHA256 = std::span<const uint8_t>{{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}};
object_id object_id::SignatureType::EcdsaSHA384 = std::span<const uint8_t>{{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03}};
object_id object_id::SignatureType::EcdsaSHA512 = std::span<const uint8_t>{{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04}};

object_id object_id::SignatureType::RsaSHA256 = std::span<const uint8_t>{{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b}};
object_id object_id::SignatureType::RsaSHA384 = std::span<const uint8_t>{{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c}};
object_id object_id::SignatureType::RsaSHA512 = std::span<const uint8_t>{{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d}};
object_id object_id::SignatureType::RsaSsaPss = std::span<const uint8_t>{{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a}};

#define FAIL() do { printf("%s:%d\n", __FILE__, __LINE__); return {}; } while (0)

bool RsaPubkey::validateSignature(Tls13SignatureScheme type, std::span<const uint8_t> data, std::span<const uint8_t> signature) const {
  switch(type) {
  case Tls13SignatureScheme::rsa_pkcs1_sha256:
    return pubkey.validatePkcs1_5Signature<Caligo::SHA2<256>>(data, signature);
  case Tls13SignatureScheme::rsa_pkcs1_sha384:
    return pubkey.validatePkcs1_5Signature<Caligo::SHA2<384>>(data, signature);
  case Tls13SignatureScheme::rsa_pkcs1_sha512:
    return pubkey.validatePkcs1_5Signature<Caligo::SHA2<512>>(data, signature);
  case Tls13SignatureScheme::rsa_pss_rsae_sha256:
  case Tls13SignatureScheme::rsa_pss_pss_sha256:
    return pubkey.validatePssSignature<Caligo::SHA2<256>, Caligo::MGF1<Caligo::SHA2<256>>>(data, signature);
  case Tls13SignatureScheme::rsa_pss_rsae_sha384:
  case Tls13SignatureScheme::rsa_pss_pss_sha384:
    return pubkey.validatePssSignature<Caligo::SHA2<384>, Caligo::MGF1<Caligo::SHA2<384>>>(data, signature);
  case Tls13SignatureScheme::rsa_pss_rsae_sha512:
  case Tls13SignatureScheme::rsa_pss_pss_sha512:
    return pubkey.validatePssSignature<Caligo::SHA2<512>, Caligo::MGF1<Caligo::SHA2<512>>>(data, signature);
  default:
    return false;
  }
}

std::vector<uint8_t> RsaPrivateKey::sign(Tls13SignatureScheme type, std::span<const uint8_t> data) const {
  std::vector<uint8_t> salt;
  switch(type) {
  case Tls13SignatureScheme::rsa_pkcs1_sha256:
    return privkey.signPkcs1_5Signature<Caligo::SHA2<256>>(data);
  case Tls13SignatureScheme::rsa_pkcs1_sha384:
    return privkey.signPkcs1_5Signature<Caligo::SHA2<384>>(data);
  case Tls13SignatureScheme::rsa_pkcs1_sha512:
    return privkey.signPkcs1_5Signature<Caligo::SHA2<512>>(data);
  case Tls13SignatureScheme::rsa_pss_rsae_sha256:
  case Tls13SignatureScheme::rsa_pss_pss_sha256:
    salt.resize(32);
    Caligo::generate_random(salt);
    return privkey.signPssSignature<Caligo::SHA2<256>, Caligo::MGF1<Caligo::SHA2<256>>>(Caligo::SHA2<256>(data).data(), salt);
  case Tls13SignatureScheme::rsa_pss_rsae_sha384:
  case Tls13SignatureScheme::rsa_pss_pss_sha384:
    salt.resize(48);
    Caligo::generate_random(salt);
    return privkey.signPssSignature<Caligo::SHA2<384>, Caligo::MGF1<Caligo::SHA2<384>>>(Caligo::SHA2<256>(data).data(), salt);
  case Tls13SignatureScheme::rsa_pss_rsae_sha512:
  case Tls13SignatureScheme::rsa_pss_pss_sha512:
    salt.resize(64);
    Caligo::generate_random(salt);
    return privkey.signPssSignature<Caligo::SHA2<512>, Caligo::MGF1<Caligo::SHA2<512>>>(Caligo::SHA2<256>(data).data(), salt);
  default:
    return {};
  }
}

template <typename T>
T parseDer(asn1_view& data);

template <>
x509date parseDer<x509date>(asn1_view& data) {
  static constexpr size_t daysInMonth[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
  auto [id, bytes] = data.read();
  if (bytes.back() != 'Z') return 0;
  std::vector<uint8_t> bytesCopy;
  if (id == asn1_id::utctime) {
    bool isPre2000 = (bytes[0] >= '5');
    bytesCopy.push_back(isPre2000 ? '1' : '2');
    bytesCopy.push_back(isPre2000 ? '9' : '0');
    bytesCopy.insert(bytesCopy.end(), bytes.begin(), bytes.end());
  } else if (id == asn1_id::generalizedtime) {
    bytesCopy.insert(bytesCopy.end(), bytes.begin(), bytes.end());
  } else return 0;
  bytesCopy.pop_back();
  for (auto& b : bytesCopy) {
    if (b < '0' || b > '9') return 0;
  }
  int year = (bytesCopy[0] - '0') * 1000 + (bytesCopy[1] - '0') * 100 + (bytesCopy[2] - '0') * 10 + (bytesCopy[3] - '0') - 1970;
  int month = (bytesCopy[4] - '0') * 10 + bytesCopy[5] - '0';
  if (month <= 0 || month > 12) return 0;
  int day = (bytesCopy[6] - '0') * 10 + bytesCopy[7] - '0';
  int hours = (bytesCopy[8] - '0') * 10 + bytesCopy[9] - '0';
  int minutes = (bytesCopy.size() >= 12) ? (bytesCopy[10] - '0') * 10 + bytesCopy[11] - '0' : 0;
  int seconds = (bytesCopy.size() >= 14) ? (bytesCopy[12] - '0') * 10 + bytesCopy[13] - '0' : 0;

  int leapdays = (year + 1) / 4;
  if (year % 4 == 2 && month > 2) leapdays++;
  return (year * 365 + (daysInMonth[month-1] + day - 1 + leapdays)) * 86400 + hours * 3600 + minutes * 60 + seconds;
}

template <>
std::string parseDer<std::string>(asn1_view& data) {
  auto [id, bytes] = data.read();
  if (id != asn1_id::printablestring && id != asn1_id::utf8string) return "";
  return std::string((const char*)bytes.data(), (const char*)bytes.data() + bytes.size());
}

std::pair<object_id, std::string> readOIDAndString(asn1_view& data) {
  auto [id, s] = data.read();
  if (id != asn1_id::set) return {{}, ""};
  asn1_view sv(s);
  auto [id2, s2] = sv.read();
  if (id2 != asn1_id::sequence) return {{}, ""};
  asn1_view sv2(s2);
  auto [id3, obj_id] = sv2.read();
  if (id3 != asn1_id::object) return {{}, ""};
  object_id oid(obj_id);
  std::string str = parseDer<std::string>(sv2);
  return {oid, str};
}

template <>
x509name parseDer<x509name>(asn1_view& data) {
  x509name rv;
  while (!data.empty()) {
    auto [oid, str] = readOIDAndString(data);
    if (oid == object_id::X509NameParts::Country) {
      rv.country = str;
    } else if (oid == object_id::X509NameParts::Organization) {
      rv.organization = str;
    } else if (oid == object_id::X509NameParts::CommonName) {
      rv.common_name = str;
    } else if (oid == object_id::X509NameParts::Surname) {
      rv.surname = str;
    } else if (oid == object_id::X509NameParts::SerialNumber) {
      rv.serialnumber = str;
    } else if (oid == object_id::X509NameParts::Locality) {
      rv.locality = str;
    } else if (oid == object_id::X509NameParts::StateOrProvince) {
      rv.state = str;
    } else if (oid == object_id::X509NameParts::StreetAddress) {
      rv.streetaddress = str;
    } else if (oid == object_id::X509NameParts::OrganizationalUnit) {
      rv.organizationalunit = str;
    } else if (oid == object_id::X509NameParts::Title) {
      rv.title = str;
    } else if (oid == object_id::X509NameParts::GivenName) {
      rv.givenname = str;
    } else if (oid == object_id::X509NameParts::EmailAddress) {
      rv.emailaddress = str;
    } else if (oid == object_id::X509NameParts::OrganizationIdentifier) {
      rv.organizationIdentifier = str;
    } else {
      FAIL();
    }
  }
  return rv;
}

template <>
int parseDer<int>(asn1_view& data) {
  auto [int_id, bytes] = data.read();
  if (int_id != asn1_id::integer) FAIL();
  std::span<const uint8_t> int_bytes = bytes;
  uint32_t value = 0;
  for (uint8_t v : int_bytes) {
    value = (value << 8) | v;
  }
  return (int)value;
}

template <size_t N>
Caligo::bignum<N> parseBignumDer(asn1_view& data) {
  auto [int_id, bytes] = data.read();
  if (int_id != asn1_id::integer) FAIL();
  std::vector<uint8_t> int_bytes;
  for (size_t n = 0; n < bytes.size(); n++) {
    int_bytes.push_back(bytes[bytes.size() - n - 1]);
  }

  // ASN1 encodes signed numbers. Given that all numbers we care about will always be unsigned,
  // many encoders "fix" this by always prefixing a 0. This makes the number too long to fit the 
  // return type though, so we don't like that.
  if (!int_bytes.empty() && int_bytes.back() == 0) int_bytes.pop_back();

  return Caligo::bignum<N>(int_bytes);
}

template <>
RsaPubkey parseDer<RsaPubkey>(asn1_view& data) {
  auto [id, d2] = data.read();
  asn1_view d(d2);
  Caligo::bignum<4096> n = parseBignumDer<4096>(d);
  Caligo::bignum<4096> e = parseBignumDer<4096>(d);
  if (e < Caligo::bignum<4096>(17)) throw std::runtime_error("Invalid public key; E is only " + std::to_string(e[0]));
  return {Caligo::rsa_public_key<4096>{n, e}};
}

template <>
std::unique_ptr<PublicKey> parseDer<std::unique_ptr<PublicKey>>(asn1_view& data) {
  auto [id1, s1] = data.read();
  if (id1 != asn1_id::sequence) FAIL();
  asn1_view s1v(s1);
  auto [id2, objid_s] = s1v.read();
  if (id2 != asn1_id::object) FAIL();
  object_id id{objid_s};
  if (id != object_id::PublicKey::RsaEncryption)
    return {};

  auto [id3, s2] = data.read();
  std::span<const uint8_t> s22 = s2.subspan(1);
  asn1_view body(s22);
  return std::make_unique<RsaPubkey>(parseDer<RsaPubkey>(body));
}

x509certificate parseCertificate(std::span<const uint8_t> in, DataFormat format) {
  std::vector<uint8_t> buffer;
  if (format == DataFormat::Pem) {  // decode pem
    std::string_view sv((const char*)in.data(), in.size());
    size_t start = sv.find("-----BEGIN CERTIFICATE-----") + strlen("-----BEGIN CERTIFICATE-----");
    size_t end = sv.find("-----END CERTIFICATE-----");
    std::string_view base64bytes = sv.substr(start, end - start);
    buffer = Caligo::base64d(base64bytes);
    in = buffer;
  }
  asn1_view in_data(in);

  auto [root_id, root_data] = in_data.read();
  if (root_id != asn1_id::sequence) FAIL();
  asn1_view data(root_data);

  auto [cert_id, cert] = data.read();
  if (cert_id != asn1_id::sequence) FAIL();

  asn1_view cdata(cert);

  x509certificate x;
  // version
  if (cdata.peek() == asn1_id::array0) {
    auto [id1, d1] = cdata.read();
    asn1_view dv1(d1);
    int version = parseDer<int>(dv1) + 1;
    if (version != 3) FAIL();
  }

  // serialnumber
  x.serialNumber = parseBignumDer<128>(cdata);

  // algorithm ID
  auto [id3, d3] = cdata.read();
  if (id3 != asn1_id::sequence) FAIL();
  // TODO

  // issuer
  auto [id4, d4] = cdata.read();
  if (id4 != asn1_id::sequence) FAIL();
  asn1_view dv4(d4);
  x.issuer = to_string(parseDer<x509name>(dv4));

  // validity
  auto [id5, d5] = cdata.read();
  if (id5 != asn1_id::sequence) FAIL();
  asn1_view d5v(d5);
  x.validity_start = parseDer<x509date>(d5v);
  x.validity_end = parseDer<x509date>(d5v);

  // subject
  auto [id6, d6] = cdata.read();
  if (id6 != asn1_id::sequence) FAIL();
  asn1_view dv6(d6);
  x509name subject = parseDer<x509name>(dv6);
  x.fqdns.insert(subject.common_name);
  x.subject = to_string(subject);

  // publicKeyInfo
  auto [id7, d7] = cdata.read();
  if (id7 != asn1_id::sequence) FAIL();
  asn1_view dv7(d7);
  x.pubkey = parseDer<std::unique_ptr<PublicKey>>(dv7);

  while (!cdata.empty()) {
    auto [id8, d8] = cdata.read();
    switch(id8) {
      case asn1_id::array1:
        // issuerUID
        break;
      case asn1_id::array2:
        // subjectUID
        break;
      case asn1_id::array3:
        // v3 extensions
        // TODO
        break;
      default:
        FAIL();
    }
  }

  x.derCert = std::vector<uint8_t>(in.data(), in.data() + in.size());
  return x;
}

std::vector<x509certificate> parseCertificatesPem(std::span<const uint8_t> in) {
  std::vector<x509certificate> certs;
  std::string_view buffer((const char*)in.data(), in.size());
  size_t start = buffer.find("-----BEGIN CERTIFICATE-----");
  size_t end = buffer.find("-----BEGIN CERTIFICATE-----", start + 1);

  while (end != std::string::npos) {
    std::string_view certpem = std::string_view(buffer).substr(start, end - start);

    std::span<const uint8_t> av(std::span<const uint8_t>((const uint8_t*)certpem.data(), certpem.size()));
    certs.push_back(parseCertificate(av, DataFormat::Pem));
    start = end;
    end = buffer.find("-----BEGIN CERTIFICATE-----", start + 1);
  }

  std::span<const uint8_t> av(std::span<const uint8_t>((const uint8_t*)buffer.data(), buffer.size()));
  certs.push_back(parseCertificate(av, DataFormat::Pem));
  return certs;
}

bool x509certificate::verify(x509certificate& issuer) {
  if (validity_start < issuer.validity_start)
    return false;
  if (validity_end > issuer.validity_end)
    return false;

  asn1_view in_data(derCert);

  auto [root_id, root_data] = in_data.read();
  if (root_id != asn1_id::sequence) return false;
  asn1_view data(root_data);

  auto [cert_id, cert] = data.read();
  if (cert_id != asn1_id::sequence) return false;

  auto [sig_id, algo] = data.read();
  auto [signature_id, sig] = data.read();
  if (sig_id != asn1_id::sequence) return false;
  if (signature_id != asn1_id::bit_string) return false;
  // Verify signature, using algo, on cert.
  // find certificate that has the correct issuer

  asn1_view algov(algo);
  auto [six, oid] = algov.read();
  std::vector<uint8_t> signature;
  for (size_t n = 0; n < sig.size() - 1; n++) {
    signature.push_back(sig[sig.size() - n - 1]);
  }
  object_id objid{oid};
  Tls13SignatureScheme type = Tls13SignatureScheme::rsa_pkcs1_sha256;
  if (objid == object_id::SignatureType::RsaSHA256) {
    type = Tls13SignatureScheme::rsa_pkcs1_sha256;
  } else if (objid == object_id::SignatureType::RsaSHA384) {
    type = Tls13SignatureScheme::rsa_pkcs1_sha384;
  } else if (objid == object_id::SignatureType::RsaSHA512) {
    type = Tls13SignatureScheme::rsa_pkcs1_sha512;
  } else {
    type = (Tls13SignatureScheme)0;
  }

  return issuer.pubkey->validateSignature(type, cert, signature);
}

std::unique_ptr<PrivateKey> parsePrivateKey(std::span<const uint8_t> in, DataFormat format) {
  std::vector<uint8_t> buffer;
  if (format == DataFormat::Pem) {  // decode pem
    std::string_view sv((const char*)in.data(), in.size());
    size_t start = sv.find("-----BEGIN RSA PRIVATE KEY-----") + strlen("-----BEGIN RSA PRIVATE KEY-----");
    size_t end = sv.find("-----END RSA PRIVATE KEY-----");
    std::string_view base64bytes = sv.substr(start, end - start);
    buffer = Caligo::base64d(base64bytes);
    in = buffer;
  }
  asn1_view in_data(in);
  auto [root_id, root_data] = in_data.read();
  if (root_id != asn1_id::sequence) FAIL();
  asn1_view data(root_data);

  /*Caligo::bignum<32> version = */parseBignumDer<32>(data);
  Caligo::bignum<4096> modulus = parseBignumDer<4096>(data);
  /*Caligo::bignum<4096> publicExponent = */parseBignumDer<4096>(data);
  Caligo::bignum<4096> privateExponent = parseBignumDer<4096>(data);
  /*
  Caligo::bignum<4096> prime1 = parseBignumDer<4096>(data);
  Caligo::bignum<4096> prime2 = parseBignumDer<4096>(data);
  Caligo::bignum<4096> exponent1 = parseBignumDer<4096>(data);
  Caligo::bignum<4096> exponent2 = parseBignumDer<4096>(data);
  Caligo::bignum<4096> coefficient = parseBignumDer<4096>(data);
*/
  return std::make_unique<RsaPrivateKey>(Caligo::rsa_private_key<4096>(modulus, privateExponent));
}

}


