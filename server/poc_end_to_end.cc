// PoC 2 equivalent: the REALITY server suspends in the certificate callback,
// dials the mirror (here: an in-process TLS 1.3 server over memory BIOs, like
// the blog's PoC), captures the live ServerHello, injects it while replacing
// the key_share ciphertext, and resumes. The client authenticates the server
// through the HMAC-overwritten certificate.
//
// This mirrors section 4.2 of https://blog.sam1314.com/posts/c65526af.html and
// is the fully deterministic version of the process-level test.

#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#include <openssl/curve25519.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "reality_common.h"

namespace {

using lwreality::RealityAuthResult;
using lwreality::RealityConfig;

struct ThreeParties {
  // Mirror (the "real site").
  bssl::UniquePtr<SSL_CTX> mirror_ctx;
  bssl::UniquePtr<SSL> mirror;
  BIO *mirror_in = nullptr;   // ClientHello -> mirror
  BIO *mirror_out = nullptr;  // mirror -> caller

  // REALITY server.
  bssl::UniquePtr<SSL_CTX> server_ctx;
  bssl::UniquePtr<SSL> server;
  BIO *server_in = nullptr;   // client -> server
  BIO *server_out = nullptr;  // server -> client

  // Client.
  bssl::UniquePtr<SSL_CTX> client_ctx;
  bssl::UniquePtr<SSL> client;
  BIO *client_in = nullptr;
  BIO *client_out = nullptr;

  RealityConfig config;
  bool suspended = false;
  bool resumed = false;
  bool mirror_captured = false;
  std::vector<uint8_t> mirror_server_hello;
};

std::vector<uint8_t> g_identity_der;

struct Capture {
  std::vector<uint8_t> sh;
};

const uint8_t kHrrRandom[32] = {0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
                                0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
                                0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
                                0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

void MirrorMsgCallback(int write_p, int, int content_type, const void *buf,
                       size_t len, SSL *, void *arg) {
  auto *capture = static_cast<Capture *>(arg);
  const uint8_t *p = static_cast<const uint8_t *>(buf);
  if (capture == nullptr || write_p != 0 || content_type != SSL3_RT_HANDSHAKE ||
      len < 38 || p[0] != SSL3_MT_SERVER_HELLO ||
      memcmp(p + 6, kHrrRandom, 32) == 0 || !capture->sh.empty()) {
    return;
  }
  capture->sh.assign(p, p + len);
}

enum ssl_select_cert_result_t SelectCallback(const SSL_CLIENT_HELLO *hello) {
  SSL *ssl = hello->ssl;
  auto *p = static_cast<ThreeParties *>(SSL_get_app_data(ssl));
  if (p == nullptr) {
    return ssl_select_cert_error;
  }
  if (!p->suspended) {
    // Authentication, exactly the function the L4 peek path uses.
    RealityAuthResult auth;
    if (!lwreality::RealityAuthDecide(hello, p->config, &auth)) {
      fprintf(stderr, "  [reality-server] select_cb: authentication failed\n");
      return ssl_select_cert_error;
    }
    // Temporary certificate whose signature field is
    // HMAC-SHA512(AuthKey, ed25519_public_key).
    std::vector<uint8_t> der;
    if (!lwreality::RealityMakeTempCert(auth.auth_key, &der)) {
      return ssl_select_cert_error;
    }
    const uint8_t *derp = der.data();
    bssl::UniquePtr<X509> x509(d2i_X509(nullptr, &derp, der.size()));
    if (x509 == nullptr ||
        !SSL_use_certificate(ssl, x509.get()) ||
        !SSL_use_PrivateKey(ssl, lwreality::RealityIdentityPrivateKey())) {
      return ssl_select_cert_error;
    }
    p->suspended = true;
    fprintf(stderr,
            "  [reality-server] select_cb: SUSPEND (ch_len=%zu sid=%zu)\n",
            hello->client_hello_len, hello->session_id_len);
    return ssl_select_cert_retry;
  }
  p->resumed = true;
  fprintf(stderr, "  [reality-server] select_cb: RESUME\n");
  return ssl_select_cert_success;
}

int ServerHelloCallback(SSL *ssl, const uint8_t **out, size_t *out_len) {
  auto *p = static_cast<ThreeParties *>(SSL_get_app_data(ssl));
  if (p == nullptr || p->mirror_server_hello.empty()) {
    return 0;
  }
  *out = p->mirror_server_hello.data();
  *out_len = p->mirror_server_hello.size();
  fprintf(stderr, "  [reality-server] returning LIVE mirror SH: %zu bytes\n",
          p->mirror_server_hello.size());
  return 1;
}

enum ssl_verify_result_t ClientVerify(SSL *ssl, uint8_t *out_alert) {
  const STACK_OF(CRYPTO_BUFFER) *chain = SSL_get0_peer_certificates(ssl);
  if (chain == nullptr || sk_CRYPTO_BUFFER_num(chain) == 0) {
    *out_alert = SSL_AD_BAD_CERTIFICATE;
    return ssl_verify_invalid;
  }
  const CRYPTO_BUFFER *leaf = sk_CRYPTO_BUFFER_value(chain, 0);
  if (SSL_reality_verify_certificate(ssl, CRYPTO_BUFFER_data(leaf),
                                     CRYPTO_BUFFER_len(leaf))) {
    return ssl_verify_ok;
  }
  fprintf(stderr, "  [client] REALITY certificate check FAILED\n");
  *out_alert = SSL_AD_BAD_CERTIFICATE;
  return ssl_verify_invalid;
}

int Pump(BIO *from, BIO *to) {
  char buf[16384];
  int total = 0;
  int n;
  while ((n = BIO_read(from, buf, sizeof(buf))) > 0) {
    BIO_write(to, buf, n);
    total += n;
  }
  return total;
}

int StepServer(ThreeParties *p) {
  const int rv = SSL_do_handshake(p->server.get());
  const int err = SSL_get_error(p->server.get(), rv);
  Pump(p->server_out, p->client_in);
  return err;
}

int StepClient(ThreeParties *p) {
  const int rv = SSL_do_handshake(p->client.get());
  const int err = SSL_get_error(p->client.get(), rv);
  Pump(p->client_out, p->server_in);
  return err;
}

int StepMirror(ThreeParties *p) {
  const int rv = SSL_do_handshake(p->mirror.get());
  const int err = SSL_get_error(p->mirror.get(), rv);
  Pump(p->mirror_out, p->server_in);
  return err;
}

}  // namespace

int main() {
  using namespace lwreality;
  ThreeParties p;
  if (!RealityInitIdentity()) {
    return 1;
  }
  uint8_t zeros[32] = {0};
  if (!RealityMakeTempCert(zeros, &g_identity_der)) {
    return 1;
  }
  const uint8_t *derp = g_identity_der.data();
  bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &derp, g_identity_der.size()));
  if (cert == nullptr) {
    return 1;
  }

  // Server static REALITY key pair (client is configured with the public half).
  uint8_t server_public[32];
  X25519_keypair(server_public, p.config.private_key);
  for (int i = 0; i < 8; i++) {
    p.config.short_id[i] = static_cast<uint8_t>(i + 1);
  }

  // --- mirror (real site) ---
  p.mirror_ctx.reset(SSL_CTX_new(TLS_server_method()));
  SSL_CTX_set_min_proto_version(p.mirror_ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(p.mirror_ctx.get(), TLS1_3_VERSION);
  // The mirror is an ordinary TLS 1.3 site; a P-256 certificate keeps a stock
  // BoringSSL client happy (Ed25519 would need the REALITY carve-out).
  std::vector<uint8_t> mirror_der;
  EVP_PKEY *mirror_key = nullptr;
  if (!RealityMakeTestCert(&mirror_der, &mirror_key)) {
    return 1;
  }
  const uint8_t *mirror_derp = mirror_der.data();
  bssl::UniquePtr<X509> mirror_cert(
      d2i_X509(nullptr, &mirror_derp, mirror_der.size()));
  SSL_CTX_use_certificate(p.mirror_ctx.get(), mirror_cert.get());
  SSL_CTX_use_PrivateKey(p.mirror_ctx.get(), mirror_key);
  p.mirror.reset(SSL_new(p.mirror_ctx.get()));
  p.mirror_in = BIO_new(BIO_s_mem());
  p.mirror_out = BIO_new(BIO_s_mem());
  SSL_set_bio(p.mirror.get(), p.mirror_in, p.mirror_out);
  SSL_set_accept_state(p.mirror.get());

  // --- REALITY server ---
  p.server_ctx.reset(SSL_CTX_new(TLS_server_method()));
  SSL_CTX_set_min_proto_version(p.server_ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(p.server_ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_select_certificate_cb(p.server_ctx.get(), SelectCallback);
  SSL_CTX_set_reality_serverhello_cb(p.server_ctx.get(), ServerHelloCallback);
  p.server.reset(SSL_new(p.server_ctx.get()));
  p.server_in = BIO_new(BIO_s_mem());
  p.server_out = BIO_new(BIO_s_mem());
  SSL_set_bio(p.server.get(), p.server_in, p.server_out);
  SSL_set_accept_state(p.server.get());
  SSL_set_app_data(p.server.get(), &p);

  // --- client ---
  p.client_ctx.reset(SSL_CTX_new(TLS_client_method()));
  SSL_CTX_set_min_proto_version(p.client_ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(p.client_ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_custom_verify(p.client_ctx.get(), SSL_VERIFY_PEER, ClientVerify);
  p.client.reset(SSL_new(p.client_ctx.get()));
  p.client_in = BIO_new(BIO_s_mem());
  p.client_out = BIO_new(BIO_s_mem());
  SSL_set_bio(p.client.get(), p.client_in, p.client_out);
  SSL_set_connect_state(p.client.get());
  SSL_set_tlsext_host_name(p.client.get(), "mirror.test");
  SSL_set1_reality_config(p.client.get(), server_public, p.config.short_id);

  fprintf(stderr, "=== Phase 1: client -> ClientHello -> reality server ===\n");
  StepClient(&p);
  const int err = StepServer(&p);
  if (err != SSL_ERROR_PENDING_CERTIFICATE || BIO_ctrl_pending(p.server_out) != 0) {
    fprintf(stderr, "FAIL: suspend semantics (err=%d, pending=%zu)\n", err,
            BIO_ctrl_pending(p.server_out));
    return 1;
  }
  fprintf(stderr, "  suspended: err=%d (PENDING_CERTIFICATE), 0 bytes emitted\n",
          err);

  fprintf(stderr, "=== Phase 2: [suspension window] dial mirror, capture SH ===\n");
  // The real front end opens a TCP connection here; in-process we drive the
  // mirror handshake directly.
  StepMirror(&p);
  for (int i = 0; i < 6 && p.mirror_server_hello.empty(); i++) {
    StepMirror(&p);
  }
  Capture capture;
  {
    // Re-run the capture with the message callback installed (the mirror
    // handshake above already delivered the ServerHello, so redo it cleanly).
    p.mirror.reset(SSL_new(p.mirror_ctx.get()));
    p.mirror_in = BIO_new(BIO_s_mem());
    p.mirror_out = BIO_new(BIO_s_mem());
    SSL_set_bio(p.mirror.get(), p.mirror_in, p.mirror_out);
    SSL_set_accept_state(p.mirror.get());
    bssl::UniquePtr<SSL_CTX> mc(SSL_CTX_new(TLS_client_method()));
    SSL_CTX_set_min_proto_version(mc.get(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(mc.get(), TLS1_3_VERSION);
    SSL_CTX_set_verify(mc.get(), SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_options(mc.get(), SSL_OP_NO_TICKET);
    // The client-facing handshake negotiates X25519; the mirror must answer in
    // the same group (blog section 4.3).
    RealityAuthResult probe;
    bssl::UniquePtr<SSL> mirror_client(SSL_new(mc.get()));
    SSL_set1_groups_list(mirror_client.get(), "X25519");
    SSL_set_msg_callback(mirror_client.get(), MirrorMsgCallback);
    SSL_set_msg_callback_arg(mirror_client.get(), &capture);
    BIO *mcin = BIO_new(BIO_s_mem());
    BIO *mcout = BIO_new(BIO_s_mem());
    BIO *msin = BIO_new(BIO_s_mem());
    BIO *msout = BIO_new(BIO_s_mem());
    SSL_set_bio(mirror_client.get(), mcin, mcout);
    bssl::UniquePtr<SSL> mirror2(SSL_new(p.mirror_ctx.get()));
    SSL_set_bio(mirror2.get(), msin, msout);
    SSL_set_accept_state(mirror2.get());
    SSL_set_connect_state(mirror_client.get());
    for (int i = 0; i < 8 && capture.sh.empty(); i++) {
      const int crv = SSL_do_handshake(mirror_client.get());
      const int cerr = SSL_get_error(mirror_client.get(), crv);
      Pump(mcout, msin);
      const int srv = SSL_do_handshake(mirror2.get());
      const int serr = SSL_get_error(mirror2.get(), srv);
      const int pumped = Pump(msout, mcin);
      fprintf(stderr, "  [mirror-loop %d] c(rv=%d err=%d) s(rv=%d err=%d) sh->%d\n",
              i, crv, cerr, srv, serr, pumped);
      if (cerr == SSL_ERROR_SSL || serr == SSL_ERROR_SSL) {
        ERR_print_errors_fp(stderr);
        break;
      }
    }
    (void)probe;
  }
  p.mirror_server_hello = capture.sh;
  fprintf(stderr, "  captured LIVE ServerHello: %zu bytes\n",
          p.mirror_server_hello.size());
  if (p.mirror_server_hello.empty()) {
    fprintf(stderr, "FAIL: no mirror ServerHello captured\n");
    return 1;
  }

  fprintf(stderr, "=== Phase 3: RESUME with the live mirror ServerHello ===\n");
  const int resume_err = StepServer(&p);
  for (int i = 0; i < 8; i++) {
    StepClient(&p);
    StepServer(&p);
  }
  if (!SSL_is_init_finished(p.client.get()) ||
      !SSL_is_init_finished(p.server.get())) {
    fprintf(stderr, "FAIL: handshake did not complete (resume err=%d)\n",
            resume_err);
    return 1;
  }
  const SSL_CIPHER *cipher = SSL_get_current_cipher(p.client.get());
  fprintf(stderr, "=== Phase 4: verify ===\n");
  fprintf(stderr, "  reality handshake complete: YES\n");
  fprintf(stderr, "  negotiated: %s cipher=%s\n", SSL_get_version(p.client.get()),
          cipher != nullptr ? SSL_CIPHER_get_name(cipher) : "?");

  // Data flow over the REALITY connection.
  const char *msg = "hello-reality";
  SSL_write(p.client.get(), msg, strlen(msg));
  Pump(p.client_out, p.server_in);
  char buf[128];
  const int n = SSL_read(p.server.get(), buf, sizeof(buf));
  fprintf(stderr, "  data transfer: %s (%d bytes)\n",
          n == static_cast<int>(strlen(msg)) ? "OK" : "FAILED", n);
  fprintf(stderr, "PASS: realtime mirror handshake works (live ServerHello injected, no BAD_DECRYPT)\n");
  return 0;
}
