#!/usr/bin/env python3
"""Applies the lightweight REALITY *client* changes to a BoringSSL tree.

Usage: apply_client_code.py <boringssl-root>

The same script is used for the PoC build tree (BoringSSL tag 0.20260413.0) and
for the naiveproxy tree (src/third_party/boringssl/src), so the code stays
byte-identical between the two. Every change is inert unless
SSL_set1_reality_config() was called on the connection.
"""
import sys
import os

HEADER_FIELDS = """  // REALITY client state. |reality_configured| is set by
  // |SSL_set1_reality_config| before the handshake. |reality_auth_key| is
  // derived while the ClientHello is built and consulted when the peer
  // certificate is verified.
  bool reality_configured = false;
  uint8_t reality_public_key[32] = {0};
  uint8_t reality_short_id[8] = {0};
  bool reality_auth_key_set = false;
  uint8_t reality_auth_key[32] = {0};

"""

API_DECLS = """
// SSL_set1_reality_config configures |ssl| as a REALITY client. |public_key| is
// the REALITY server's static X25519 public key and |short_id| is the short id
// sent in the sealed ClientHello session id. It must be called before the
// handshake; when it is not called, |ssl| is an ordinary BoringSSL client.
OPENSSL_EXPORT int SSL_set1_reality_config(SSL *ssl,
                                           const uint8_t public_key[32],
                                           const uint8_t short_id[8]);

// SSL_reality_verify_certificate checks a REALITY server certificate. It
// returns one when the leaf certificate's signature field equals
// HMAC-SHA512(AuthKey, leaf_ed25519_public_key), which proves the peer derived
// the same authentication key from the ClientHello session id. |leaf_der| is
// the DER-encoded leaf certificate. It returns zero when REALITY is not
// configured on |ssl| or the check fails.
OPENSSL_EXPORT int SSL_reality_verify_certificate(SSL *ssl,
                                                  const uint8_t *leaf_der,
                                                  size_t leaf_der_len);
"""

CLIENT_HELPERS = """// REALITY: derives the authentication key
//   HKDF-SHA256(X25519(client ephemeral private key, server static public key),
//               salt = client_random[0:20], info = "REALITY")
// from the X25519 key share this client offers. Returns true on success.
static bool reality_derive_auth_key(SSL_HANDSHAKE *hs, uint8_t out_key[32]) {
  SSL *const ssl = hs->ssl;
  uint8_t private_key[32];
  bool found = false;
  for (const auto &key_share : hs->key_shares) {
    if (key_share->GroupID() != SSL_GROUP_X25519) {
      continue;
    }
    ScopedCBB cbb;
    uint8_t *data = nullptr;
    size_t len = 0;
    if (!CBB_init(cbb.get(), 32) || !key_share->SerializePrivateKey(cbb.get()) ||
        !CBB_finish(cbb.get(), &data, &len)) {
      return false;
    }
    if (len != sizeof(private_key)) {
      OPENSSL_free(data);
      return false;
    }
    OPENSSL_memcpy(private_key, data, sizeof(private_key));
    OPENSSL_free(data);
    found = true;
    break;
  }
  if (!found || ssl->s3 == nullptr) {
    return false;
  }
  uint8_t shared_key[32];
  static const uint8_t kInfo[] = "REALITY";
  if (!X25519(shared_key, private_key, ssl->reality_public_key) ||
      !HKDF(out_key, 32, EVP_sha256(), shared_key, sizeof(shared_key),
            ssl->s3->client_random, 20, kInfo, sizeof(kInfo) - 1)) {
    return false;
  }
  return true;
}

// REALITY: seals the client version, a timestamp and the short id into the
// ClientHello's legacy session id. Called after the ClientHello has been built
// and before it is hashed and sent, so the transcript and the wire bytes agree.
static bool reality_patch_client_hello(SSL_HANDSHAKE *hs, Array<uint8_t> *msg) {
  SSL *const ssl = hs->ssl;
  if (!ssl->reality_configured) {
    return true;
  }
  // The legacy session id contents are at offset 39: 4-byte handshake header,
  // 2-byte legacy_version, 32-byte random, then the one-byte session-id length.
  static const size_t kSessionIdOffset = 39;
  static const size_t kSessionIdLength = 32;
  static const uint8_t kClientVersion[3] = {1, 0, 0};
  if (msg->size() < kSessionIdOffset + kSessionIdLength ||
      hs->session_id.size() != kSessionIdLength || ssl->s3 == nullptr) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return false;
  }
  uint8_t auth_key[32];
  if (!reality_derive_auth_key(hs, auth_key)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return false;
  }
  // The sealed blob is 16 bytes of payload (version, timestamp, short id) plus
  // the 16-byte AEAD tag, filling the 32-byte session id exactly.
  uint8_t plaintext[16] = {0};
  plaintext[0] = kClientVersion[0];
  plaintext[1] = kClientVersion[1];
  plaintext[2] = kClientVersion[2];
  plaintext[3] = 0;  // reserved
  const uint32_t timestamp = static_cast<uint32_t>(time(nullptr));
  plaintext[4] = static_cast<uint8_t>(timestamp >> 24);
  plaintext[5] = static_cast<uint8_t>(timestamp >> 16);
  plaintext[6] = static_cast<uint8_t>(timestamp >> 8);
  plaintext[7] = static_cast<uint8_t>(timestamp);
  OPENSSL_memcpy(plaintext + 8, ssl->reality_short_id, 8);

  // The AEAD additional data is the ClientHello with a zeroed session id,
  // matching what the server reconstructs.
  OPENSSL_memset(msg->data() + kSessionIdOffset, 0, kSessionIdLength);
  EVP_AEAD_CTX aead_ctx;
  if (!EVP_AEAD_CTX_init(&aead_ctx, EVP_aead_aes_256_gcm(), auth_key,
                         sizeof(auth_key), 0, nullptr)) {
    return false;
  }
  uint8_t sealed[32];
  size_t sealed_len = 0;
  const bool ok = EVP_AEAD_CTX_seal(
      &aead_ctx, sealed, &sealed_len, sizeof(sealed), ssl->s3->client_random + 20,
      12, plaintext, sizeof(plaintext), msg->data(), msg->size());
  EVP_AEAD_CTX_cleanup(&aead_ctx);
  if (!ok || sealed_len != sizeof(sealed)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return false;
  }
  OPENSSL_memcpy(msg->data() + kSessionIdOffset, sealed, sizeof(sealed));
  OPENSSL_memcpy(hs->session_id.data(), sealed, sizeof(sealed));
  OPENSSL_memcpy(ssl->reality_auth_key, auth_key, sizeof(auth_key));
  ssl->reality_auth_key_set = true;
  return true;
}

"""

LIB_IMPL = """
int SSL_set1_reality_config(SSL *ssl, const uint8_t public_key[32],
                            const uint8_t short_id[8]) {
  if (ssl == nullptr || public_key == nullptr || short_id == nullptr) {
    return 0;
  }
  OPENSSL_memcpy(ssl->reality_public_key, public_key, 32);
  OPENSSL_memcpy(ssl->reality_short_id, short_id, 8);
  ssl->reality_configured = true;
  return 1;
}

int SSL_reality_verify_certificate(SSL *ssl, const uint8_t *leaf_der,
                                   size_t leaf_der_len) {
  if (ssl == nullptr || !ssl->reality_configured ||
      !ssl->reality_auth_key_set || leaf_der == nullptr) {
    return 0;
  }
  const uint8_t *p = leaf_der;
  bssl::UniquePtr<X509> leaf(d2i_X509(nullptr, &p, leaf_der_len));
  if (leaf == nullptr) {
    return 0;
  }
  EVP_PKEY *pubkey = X509_get0_pubkey(leaf.get());
  if (pubkey == nullptr || EVP_PKEY_id(pubkey) != EVP_PKEY_ED25519) {
    return 0;
  }
  uint8_t raw_public_key[32];
  size_t raw_public_key_len = sizeof(raw_public_key);
  if (!EVP_PKEY_get_raw_public_key(pubkey, raw_public_key,
                                   &raw_public_key_len) ||
      raw_public_key_len != sizeof(raw_public_key)) {
    return 0;
  }
  const ASN1_BIT_STRING *signature = nullptr;
  X509_get0_signature(&signature, nullptr, leaf.get());
  if (signature == nullptr || ASN1_STRING_length(signature) != 64) {
    return 0;
  }
  uint8_t expected[64];
  unsigned int expected_len = 0;
  if (HMAC(EVP_sha512(), ssl->reality_auth_key, 32, raw_public_key,
           sizeof(raw_public_key), expected,
           &expected_len) == nullptr ||
      expected_len != sizeof(expected)) {
    return 0;
  }
  return CRYPTO_memcmp(expected, ASN1_STRING_get0_data(signature), 64) == 0;
}
"""


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write(path, data):
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)


def insert_after(text, anchor, addition, what):
    if addition.strip() in text:
        print("  already applied: %s" % what)
        return text
    idx = text.find(anchor)
    if idx < 0:
        raise SystemExit("anchor not found for %s" % what)
    end = idx + len(anchor)
    print("  applied: %s" % what)
    return text[:end] + addition + text[end:]


def insert_before(text, anchor, addition, what):
    if addition.strip() in text:
        print("  already applied: %s" % what)
        return text
    idx = text.find(anchor)
    if idx < 0:
        raise SystemExit("anchor not found for %s" % what)
    print("  applied: %s" % what)
    return text[:idx] + addition + text[idx:]


def main():
    root = sys.argv[1]
    opaque = len(sys.argv) > 2 and sys.argv[2] == "--opaque"
    lib_impl = LIB_IMPL
    if opaque:
        # Newer BoringSSL spells SSL* field access as FromOpaque(ssl)->.
        lib_impl = lib_impl.replace("ssl->reality_", "FromOpaque(ssl)->reality_")
    print("patching %s" % root)

    # 1. ssl/internal.h: per-connection REALITY state.
    path = os.path.join(root, "ssl/internal.h")
    text = read(path)
    text = insert_before(text, "  bool server : 1;", HEADER_FIELDS,
                         "ssl/internal.h fields")
    write(path, text)

    # 2. include/openssl/ssl.h: public API.
    path = os.path.join(root, "include/openssl/ssl.h")
    text = read(path)
    text = insert_after(
        text,
        "OPENSSL_EXPORT void SSL_CTX_set_reverify_on_resume(SSL_CTX *ctx, "
        "int enabled);",
        API_DECLS, "ssl.h declarations")
    write(path, text)

    # 3. ssl/handshake_client.cc: seal the session id while building the CH.
    path = os.path.join(root, "ssl/handshake_client.cc")
    text = read(path)
    if "#include <openssl/curve25519.h>" not in text:
        text = insert_after(text, "#include <openssl/bytestring.h>\n",
                            "#include <openssl/curve25519.h>\n"
                            "#include <openssl/digest.h>\n"
                            "#include <openssl/hkdf.h>\n", "client includes")
    text = insert_after(text, "#include <string.h>\n", "#include <time.h>\n",
                        "client time.h")
    text = insert_before(text, "bool ssl_add_client_hello(SSL_HANDSHAKE *hs) {",
                         CLIENT_HELPERS, "client helpers")
    text = insert_after(
        text,
        "      !ssl->method->finish_message(ssl, cbb.get(), &msg)) {\n"
        "    return false;\n"
        "  }\n",
        "\n  // REALITY: seal the authentication blob into the session id before\n"
        "  // the ClientHello is hashed and sent.\n"
        "  if (!reality_patch_client_hello(hs, &msg)) {\n"
        "    return false;\n"
        "  }\n", "client hello hook")
    write(path, text)

    # 4. ssl/extensions.cc: accept the unadvertised Ed25519 CertificateVerify.
    path = os.path.join(root, "ssl/extensions.cc")
    text = read(path)
    old = """  if (std::find(sigalgs.begin(), sigalgs.end(), sigalg) == sigalgs.end() ||
      !ssl_pkey_supports_algorithm(hs->ssl, pkey, sigalg, /*is_verify=*/true)) {"""
    new = """  // REALITY: the server signs CertificateVerify with an Ed25519 certificate
  // that Chrome-family clients do not advertise. Allow this one signature
  // scheme only when REALITY is configured on the connection, and leave the
  // advertised list untouched.
  const bool is_reality_ed25519 =
      hs->ssl->reality_configured && sigalg == SSL_SIGN_ED25519;
  if ((std::find(sigalgs.begin(), sigalgs.end(), sigalg) == sigalgs.end() &&
       !is_reality_ed25519) ||
      !ssl_pkey_supports_algorithm(hs->ssl, pkey, sigalg, /*is_verify=*/true)) {"""
    if "is_reality_ed25519" in text:
        print("  already applied: sigalg carve-out")
    elif old in text:
        text = text.replace(old, new, 1)
        print("  applied: sigalg carve-out")
    else:
        raise SystemExit("sigalg carve-out anchor not found")
    write(path, text)

    # 5. ssl/ssl_lib.cc: the two exported functions.
    path = os.path.join(root, "ssl/ssl_lib.cc")
    text = read(path)
    if "#include <openssl/hmac.h>" not in text:
        text = insert_after(text, "#include <openssl/evp.h>\n",
                            "#include <openssl/hmac.h>\n"
                            "#include <openssl/x509.h>\n", "ssl_lib includes")
    if lib_impl.strip() not in text:
        sig = "void SSL_CTX_set_select_certificate_cb(\n    SSL_CTX *ctx,\n    enum ssl_select_cert_result_t (*cb)(const SSL_CLIENT_HELLO *)) {"
        idx = text.find(sig)
        if idx < 0:
            raise SystemExit("anchor not found for ssl_lib implementations")
        end = text.index("\n}\n", idx) + 3
        text = text[:end] + "\n" + lib_impl + text[end:]
        print("  applied: ssl_lib implementations")
    else:
        print("  already applied: ssl_lib implementations")
    write(path, text)

    print("done")


if __name__ == "__main__":
    main()
