// Lightweight REALITY: shared authentication / certificate helpers.

#include "reality_common.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/aead.h>
#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/curve25519.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/nid.h>
#include <openssl/hkdf.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/x509.h>

namespace lwreality {
namespace {

// The process-wide Ed25519 identity, created once by RealityInitIdentity().
uint8_t g_identity_public[32] = {0};
EVP_PKEY *g_identity_private = nullptr;
// DER of the blank self-signed certificate; its signature field is replaced per
// connection.
std::vector<uint8_t> g_blank_cert_der;
bool g_identity_ready = false;

bool MakeBlankCertificate() {
  bssl::UniquePtr<EVP_PKEY> public_key(
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, g_identity_public,
                                  sizeof(g_identity_public)));
  bssl::UniquePtr<X509> x509(X509_new());
  if (public_key == nullptr || x509 == nullptr) {
    return false;
  }
  bssl::UniquePtr<X509_NAME> name(X509_NAME_new());
  if (name == nullptr ||
      !X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_UTF8,
                                  reinterpret_cast<const uint8_t *>("reality"),
                                  -1, -1, 0)) {
    return false;
  }
  if (!X509_set_version(x509.get(), 2) ||
      !ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1) ||
      !X509_gmtime_adj(X509_getm_notBefore(x509.get()), 0) ||
      !X509_gmtime_adj(X509_getm_notAfter(x509.get()), 60L * 60 * 24 * 365) ||
      !X509_set_subject_name(x509.get(), name.get()) ||
      !X509_set_issuer_name(x509.get(), name.get()) ||
      !X509_set_pubkey(x509.get(), public_key.get()) ||
      // Ed25519 signs the message directly; the digest must be null.
      !X509_sign(x509.get(), g_identity_private, nullptr)) {
    return false;
  }
  uint8_t *der = nullptr;
  const int der_len = i2d_X509(x509.get(), &der);
  if (der_len <= 0) {
    return false;
  }
  g_blank_cert_der.assign(der, der + der_len);
  OPENSSL_free(der);
  return g_blank_cert_der.size() > 64;
}

}  // namespace

bool RealityInitIdentity() {
  if (g_identity_ready) {
    return true;
  }
  // ED25519_keypair writes a 64-byte private key (seed || public key); the
  // raw private key understood by EVP is the 32-byte seed.
  uint8_t private_key[64];
  ED25519_keypair(g_identity_public, private_key);
  g_identity_private =
      EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key, 32);
  if (g_identity_private == nullptr || !MakeBlankCertificate()) {
    return false;
  }
  g_identity_ready = true;
  return true;
}

const uint8_t *RealityIdentityPublicKey() { return g_identity_public; }

EVP_PKEY *RealityIdentityPrivateKey() { return g_identity_private; }

bool RealityMakeTempCert(const uint8_t auth_key[32], std::vector<uint8_t> *out) {
  if (!g_identity_ready || g_blank_cert_der.size() <= 64) {
    return false;
  }
  std::vector<uint8_t> der = g_blank_cert_der;
  uint8_t mac[64];
  unsigned int mac_len = 0;
  if (HMAC(EVP_sha512(), auth_key, 32, g_identity_public,
           sizeof(g_identity_public), mac, &mac_len) == nullptr ||
      mac_len != 64) {
    return false;
  }
  // The last 64 bytes of an Ed25519 certificate are the signature; overwrite
  // them so a REALITY client can recognise the server (XTLS/REALITY does the
  // same in handshake_server_tls13.go).
  memcpy(der.data() + der.size() - 64, mac, 64);
  *out = std::move(der);
  return true;
}

bool FindKeyShare(const SSL_CLIENT_HELLO *ch, uint16_t want_group,
                  uint16_t *group_out, const uint8_t **key_out,
                  size_t *key_len_out) {
  const uint8_t *extensions = nullptr;
  size_t extensions_len = 0;
  if (!SSL_early_callback_ctx_extension_get(ch, kExtensionKeyShare, &extensions,
                                            &extensions_len)) {
    return false;
  }
  // The extension body is a length-prefixed list of KeyShareEntry values.
  CBS extension(bssl::Span<const uint8_t>(extensions, extensions_len));
  CBS shares;
  if (!CBS_get_u16_length_prefixed(&extension, &shares)) {
    return false;
  }
  while (CBS_len(&shares) > 0) {
    uint16_t group_id;
    CBS key;
    if (!CBS_get_u16(&shares, &group_id) ||
        !CBS_get_u16_length_prefixed(&shares, &key)) {
      return false;
    }
    if (want_group == 0 || group_id == want_group) {
      *group_out = group_id;
      *key_out = CBS_data(&key);
      *key_len_out = CBS_len(&key);
      return true;
    }
  }
  return false;
}

bool RealityAuthDecide(const SSL_CLIENT_HELLO *ch, const RealityConfig &config,
                       RealityAuthResult *out) {
  if (ch->random_len != 32 || ch->session_id_len != kSessionIdLength ||
      ch->client_hello_len < kSessionIdOffset + kSessionIdLength) {
    return false;
  }

  // The mirror must be dialed with the client's first offered group; the ECDH
  // for authentication may use any X25519 share (blog section 4.3).
  uint16_t first_group = 0;
  const uint8_t *first_key = nullptr;
  size_t first_key_len = 0;
  if (!FindKeyShare(ch, /*want_group=*/0, &first_group, &first_key,
                    &first_key_len)) {
    return false;
  }
  uint16_t x25519_group = 0;
  const uint8_t *x25519_key = nullptr;
  size_t x25519_key_len = 0;
  const bool has_x25519 =
      FindKeyShare(ch, kGroupX25519, &x25519_group, &x25519_key,
                   &x25519_key_len) &&
      x25519_key_len == 32;

  // |ch->client_hello| points at the ClientHello body, but the client sealed
  // the complete handshake message, so rebuild the four-byte handshake header
  // (type + 24-bit length) in front of it. The additional data is then the
  // message with a zeroed legacy_session_id, exactly what the client hashed.
  std::vector<uint8_t> aad;
  aad.reserve(ch->client_hello_len + 4);
  aad.push_back(SSL3_MT_CLIENT_HELLO);
  aad.push_back(static_cast<uint8_t>(ch->client_hello_len >> 16));
  aad.push_back(static_cast<uint8_t>(ch->client_hello_len >> 8));
  aad.push_back(static_cast<uint8_t>(ch->client_hello_len));
  aad.insert(aad.end(), ch->client_hello,
             ch->client_hello + ch->client_hello_len);
  if (aad.size() < kSessionIdOffset + kSessionIdLength) {
    return false;
  }
  memset(aad.data() + kSessionIdOffset, 0, kSessionIdLength);

  std::vector<uint16_t> ciphers;
  CBS cipher_suites(bssl::Span<const uint8_t>(ch->cipher_suites, ch->cipher_suites_len));
  while (CBS_len(&cipher_suites) > 0) {
    uint16_t cipher;
    if (!CBS_get_u16(&cipher_suites, &cipher)) {
      return false;
    }
    ciphers.push_back(cipher);
  }

  RealityAuthResult result;
  memcpy(result.client_random, ch->random, 32);
  result.first_group = first_group;
  result.first_key_share.assign(first_key, first_key + first_key_len);
  result.has_x25519 = has_x25519;
  if (has_x25519) {
    memcpy(result.x25519_key_share, x25519_key, 32);
  }
  result.client_hello = aad;
  result.client_ciphers = std::move(ciphers);
  result.session_id.assign(ch->session_id, ch->session_id + ch->session_id_len);

  if (!result.has_x25519) {
    return false;
  }

  uint8_t shared[32];
  if (!X25519(shared, config.private_key, result.x25519_key_share)) {
    return false;
  }
  uint8_t auth_key[32];
  static const uint8_t kInfo[] = "REALITY";
  if (!HKDF(auth_key, sizeof(auth_key), EVP_sha256(), shared, sizeof(shared),
            result.client_random, 20, kInfo, sizeof(kInfo) - 1)) {
    return false;
  }

  EVP_AEAD_CTX aead_ctx;
  if (!EVP_AEAD_CTX_init(&aead_ctx, EVP_aead_aes_256_gcm(), auth_key,
                         sizeof(auth_key), 0, nullptr)) {
    return false;
  }
  // The sealed blob is 16 bytes of payload (version, timestamp, short id) plus
  // the 16-byte AEAD tag, filling the 32-byte session id exactly.
  uint8_t plaintext[16];
  size_t plaintext_len = 0;
  const bool opened = EVP_AEAD_CTX_open(
      &aead_ctx, plaintext, &plaintext_len, sizeof(plaintext),
      result.client_random + 20, 12, result.session_id.data(),
      result.session_id.size(), result.client_hello.data(),
      result.client_hello.size());
  EVP_AEAD_CTX_cleanup(&aead_ctx);
  if (!opened || plaintext_len != sizeof(plaintext)) {
    return false;
  }

  if (plaintext[0] != kClientVersion[0] || plaintext[1] != kClientVersion[1] ||
      plaintext[2] != kClientVersion[2] || plaintext[3] != 0) {
    return false;
  }
  const uint32_t timestamp = (static_cast<uint32_t>(plaintext[4]) << 24) |
                             (static_cast<uint32_t>(plaintext[5]) << 16) |
                             (static_cast<uint32_t>(plaintext[6]) << 8) |
                             static_cast<uint32_t>(plaintext[7]);
  const int64_t now = static_cast<int64_t>(time(nullptr));
  const int64_t diff = now - static_cast<int64_t>(timestamp);
  if (diff > config.max_time_diff_seconds ||
      diff < -config.max_time_diff_seconds) {
    return false;
  }
  if (CRYPTO_memcmp(plaintext + 8, config.short_id, 8) != 0) {
    return false;
  }

  memcpy(result.auth_key, auth_key, sizeof(auth_key));
  result.ok = true;
  *out = std::move(result);
  return true;
}

bool RealityMakeTestCert(std::vector<uint8_t> *der_out, EVP_PKEY **key_out) {
  bssl::UniquePtr<EVP_PKEY> key(EVP_PKEY_new());
  bssl::UniquePtr<EC_KEY> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  if (key == nullptr || ec == nullptr || !EC_KEY_generate_key(ec.get()) ||
      !EVP_PKEY_set1_EC_KEY(key.get(), ec.get())) {
    return false;
  }
  bssl::UniquePtr<X509> x509(X509_new());
  bssl::UniquePtr<X509_NAME> name(X509_NAME_new());
  if (x509 == nullptr || name == nullptr ||
      !X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_UTF8,
                                  reinterpret_cast<const uint8_t *>("mirror"),
                                  -1, -1, 0) ||
      !X509_set_version(x509.get(), 2) ||
      !ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 3) ||
      !X509_gmtime_adj(X509_getm_notBefore(x509.get()), 0) ||
      !X509_gmtime_adj(X509_getm_notAfter(x509.get()), 3600) ||
      !X509_set_subject_name(x509.get(), name.get()) ||
      !X509_set_issuer_name(x509.get(), name.get()) ||
      !X509_set_pubkey(x509.get(), key.get()) ||
      !X509_sign(x509.get(), key.get(), EVP_sha256())) {
    return false;
  }
  uint8_t *der = nullptr;
  const int der_len = i2d_X509(x509.get(), &der);
  if (der_len <= 0) {
    return false;
  }
  der_out->assign(der, der + der_len);
  OPENSSL_free(der);
  *key_out = key.release();
  return true;
}

bool HexDecode(const std::string &hex, std::vector<uint8_t> *out) {
  if (hex.size() % 2 != 0) {
    return false;
  }
  out->clear();
  for (size_t i = 0; i < hex.size(); i += 2) {
    auto nibble = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    const int hi = nibble(hex[i]);
    const int lo = nibble(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out->push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return true;
}

}  // namespace lwreality
