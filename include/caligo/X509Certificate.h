#pragma once

#include <caligo/Asn1.h>

#include <caligo/bignum.h>
#include <caligo/rsa.h>

#include <string>
#include <unordered_set>

namespace Caligo {

using x509date = uint64_t;
using x509id = std::vector<uint8_t>;

struct x509name {
  std::string common_name;
  std::string country;
  std::string emailaddress;
  std::string givenname;
  std::string locality;
  std::string organization;
  std::string organizationIdentifier;
  std::string organizationalunit;
  std::string serialnumber;
  std::string state;
  std::string streetaddress;
  std::string surname;
  std::string title;

  friend std::string to_string(const x509name& name) {
    std::string accum;
    if (!name.serialnumber.empty()) accum += "S#=" + name.serialnumber + " ";
    if (!name.country.empty()) accum += "C=" + name.country + " ";

    if (!name.locality.empty()) accum += "L=" + name.locality + " ";
    if (!name.streetaddress.empty()) accum += "STREET=" + name.streetaddress + " ";
    if (!name.state.empty()) accum += "ST=" + name.state + " ";

    if (!name.emailaddress.empty()) accum += "E=" + name.emailaddress + " ";
    if (!name.givenname.empty()) accum += "GN=" + name.givenname + " ";
    if (!name.surname.empty()) accum += "SN=" + name.surname + " ";
    if (!name.title.empty()) accum += "T=" + name.title + " ";

    if (!name.organization.empty()) accum += "O=" + name.organization + " ";
    if (!name.organizationIdentifier.empty()) accum += "OI=" + name.organizationIdentifier + " ";
    if (!name.organizationalunit.empty()) accum += "OU=" + name.organizationalunit + " ";

    if (!name.common_name.empty()) accum += "CN=" + name.common_name + " ";

    if (!accum.empty()) accum.pop_back();
    return accum;
  }
};

struct object_id {
  struct PublicKey { // namespace, but can't put namespace here
    static object_id RsaEncryption;
    static object_id RsaSsaPss;
    static object_id EcPublicKey;
    static object_id X25519;
    static object_id X448;
  };
  struct X509NameParts {
    static object_id CommonName;
    static object_id Surname;
    static object_id SerialNumber;
    static object_id Country;
    static object_id Locality;
    static object_id StateOrProvince;
    static object_id StreetAddress;
    static object_id Organization;
    static object_id OrganizationIdentifier;
    static object_id OrganizationalUnit;
    static object_id Title;
    static object_id GivenName;
    static object_id EmailAddress;
  };

  struct SignatureType {
    static object_id Ed25519;
    static object_id Ed448;
    static object_id EcdsaSHA256;
    static object_id EcdsaSHA384;
    static object_id EcdsaSHA512;
    static object_id RsaSHA256;
    static object_id RsaSHA384;
    static object_id RsaSHA512;
    static object_id RsaSsaPss;
  };

  object_id() 
  {
  }
  object_id(std::span<const uint8_t> data)
  : data(data.data(), data.data() + data.size())
  {}
  std::vector<uint8_t> data;
  bool operator==(const object_id& o) const = default;
};

enum Tls13SignatureScheme {
  rsa_pkcs1_sha256 = 0x0401,
  rsa_pkcs1_sha384 = 0x0501,
  rsa_pkcs1_sha512 = 0x0601,
  rsa_pss_rsae_sha256 = 0x0804,
  rsa_pss_rsae_sha384 = 0x0805,
  rsa_pss_rsae_sha512 = 0x0806,
  rsa_pss_pss_sha256 = 0x0809,
  rsa_pss_pss_sha384 = 0x080a,
  rsa_pss_pss_sha512 = 0x080b,

  ecdsa_secp256r1_sha256 = 0x0403,
  ecdsa_secp384r1_sha384 = 0x0503,
  ecdsa_secp521r1_sha512 = 0x0603,
  ed25519 = 0x0807,
  ed448 = 0x0808,
};

struct PublicKey {
  virtual ~PublicKey() = default;
  virtual bool validateSignature(Tls13SignatureScheme type, std::span<const uint8_t>, std::span<const uint8_t>) const = 0;
};

struct RsaPubkey : PublicKey {
  Caligo::rsa_public_key<4096> pubkey;
  RsaPubkey(Caligo::rsa_public_key<4096> pubkey)
  : pubkey(pubkey)
  {}
  bool validateSignature(Tls13SignatureScheme type, std::span<const uint8_t> data, std::span<const uint8_t> signature) const override;
};

struct PrivateKey {
  virtual ~PrivateKey() = default;
  virtual std::vector<uint8_t> sign(Tls13SignatureScheme type, std::span<const uint8_t> message) const = 0;
};

struct RsaPrivateKey : PrivateKey {
  Caligo::rsa_private_key<4096> privkey;
  RsaPrivateKey(Caligo::rsa_private_key<4096> privkey)
  : privkey(privkey)
  {}
  std::vector<uint8_t> sign(Tls13SignatureScheme type, std::span<const uint8_t> message) const override;
};

struct x509certificate {
  std::vector<uint8_t> derCert;
  Caligo::bignum<128> serialNumber;
  // algorithm identifier?
  std::unordered_set<std::string> fqdns;
  std::string subject;
  std::string issuer;

  x509date validity_start;
  x509date validity_end;

  // public key, somehow
  std::unique_ptr<PublicKey> pubkey; // local ptr?

  // v3 extensions


  bool appliesTo(const std::string& fqdn) {
    return fqdns.find(fqdn) != fqdns.end();
  }
  bool verify(x509certificate& issuer);
};

enum class DataFormat {
  Der,
  Pem,
};

std::vector<x509certificate> parseCertificatesPem(std::span<const uint8_t> in);
x509certificate parseCertificate(std::span<const uint8_t> in, DataFormat format = DataFormat::Der);
std::unique_ptr<PrivateKey> parsePrivateKey(std::span<const uint8_t> in, DataFormat format = DataFormat::Der);

}


