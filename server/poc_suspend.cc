// PoC 1 equivalent: proves the suspension primitive. The certificate selection
// callback returns ssl_select_cert_retry on the first call, the handshake
// returns SSL_ERROR_PENDING_CERTIFICATE (12) with zero bytes emitted, and a
// second call resumes it to completion.
//
// This mirrors section 4.1 of https://blog.sam1314.com/posts/c65526af.html.

#include <stdio.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "reality_common.h"

namespace {

int g_call_count = 0;
bool g_resumed = false;

enum ssl_select_cert_result_t SelectCallback(const SSL_CLIENT_HELLO *hello) {
  g_call_count++;
  fprintf(stderr, "[select_cb] #%d ch_len=%zu sid=%zu\n", g_call_count,
          hello->client_hello_len, hello->session_id_len);
  if (!g_resumed) {
    fprintf(stderr, "    -> ssl_select_cert_retry  [SUSPEND]\n");
    return ssl_select_cert_retry;
  }
  fprintf(stderr, "    -> ssl_select_cert_success [RESUME]\n");
  return ssl_select_cert_success;
}

// Builds a throwaway ECDSA P-256 self-signed certificate, like the "cert.pem"
// of the blog's PoC. PoC 1 only exercises the suspension primitive, so the
// certificate does not matter; a P-256 key keeps the stock BoringSSL client
// happy (Ed25519 would need the REALITY client carve-out).
bool MakeTestCertificate(std::vector<uint8_t> *der_out, EVP_PKEY **key_out) {
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
                                  reinterpret_cast<const uint8_t *>("reality"),
                                  -1, -1, 0) ||
      !X509_set_version(x509.get(), 2) ||
      !ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 2) ||
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

// A REALITY server always installs the ServerHello hook; returning zero keeps
// BoringSSL's own ServerHello while enabling the Ed25519 signature algorithm
// carve-out.
int NoMirror(SSL *, const uint8_t **, size_t *) { return 0; }

int Step(SSL *ssl, BIO *out, BIO *peer_in) {
  const int ret = SSL_do_handshake(ssl);
  const int err = SSL_get_error(ssl, ret);
  char buf[16384];
  int n;
  while ((n = BIO_read(out, buf, sizeof(buf))) > 0) {
    BIO_write(peer_in, buf, n);
  }
  return err;
}

}  // namespace

int main() {
  using namespace lwreality;
  std::vector<uint8_t> der;
  EVP_PKEY *test_key = nullptr;
  if (!MakeTestCertificate(&der, &test_key)) {
    return 1;
  }
  const uint8_t *p = der.data();
  bssl::UniquePtr<X509> x509(d2i_X509(nullptr, &p, der.size()));

  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_server_method()));
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_client_method()));
  SSL_CTX_set_select_certificate_cb(server_ctx.get(), SelectCallback);
  SSL_CTX_set_reality_serverhello_cb(server_ctx.get(), NoMirror);
  SSL_CTX_use_certificate(server_ctx.get(), x509.get());
  SSL_CTX_use_PrivateKey(server_ctx.get(), test_key);
  SSL_CTX_set_min_proto_version(server_ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION);

  bssl::UniquePtr<SSL> client(SSL_new(client_ctx.get()));
  bssl::UniquePtr<SSL> server(SSL_new(server_ctx.get()));
  SSL_set_tlsext_host_name(client.get(), "reality.test");
  BIO *c_in = BIO_new(BIO_s_mem()), *c_out = BIO_new(BIO_s_mem());
  BIO *s_in = BIO_new(BIO_s_mem()), *s_out = BIO_new(BIO_s_mem());
  SSL_set_bio(client.get(), c_in, c_out);
  SSL_set_bio(server.get(), s_in, s_out);
  SSL_set_connect_state(client.get());
  SSL_set_accept_state(server.get());

  Step(client.get(), c_out, s_in);  // ClientHello -> server
  const int err = Step(server.get(), s_out, c_in);
  if (err != SSL_ERROR_PENDING_CERTIFICATE) {
    fprintf(stderr, "FAIL: expected SSL_ERROR_PENDING_CERTIFICATE, got %d\n", err);
    return 1;
  }
  if (BIO_ctrl_pending(s_out) != 0) {
    fprintf(stderr, "FAIL: server emitted %zu bytes while suspended\n",
            BIO_ctrl_pending(s_out));
    return 1;
  }
  fprintf(stderr, "    -> err=%d (SSL_ERROR_PENDING_CERTIFICATE), 0 bytes emitted\n",
          err);

  g_resumed = true;
  for (int i = 0; i < 12; i++) {
    Step(server.get(), s_out, c_in);
    Step(client.get(), c_out, s_in);
    if (SSL_is_init_finished(client.get()) && SSL_is_init_finished(server.get())) {
      break;
    }
  }
  const bool ok = SSL_is_init_finished(client.get()) &&
                  SSL_is_init_finished(server.get());
  fprintf(stderr, "client init: %s  server init: %s  select_cb calls: %d  %s\n",
          SSL_is_init_finished(client.get()) ? "YES" : "NO",
          SSL_is_init_finished(server.get()) ? "YES" : "NO", g_call_count,
          ok ? "PASS: suspend-resume closed loop works" : "FAIL");
  return ok ? 0 : 1;
}
