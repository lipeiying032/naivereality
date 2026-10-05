// PoC client: a REALITY client built on the patched BoringSSL. This is the same
// sequence the naiveproxy client patch performs in Chromium:
//   1. SSL_set1_reality_config()  -> seal the session id while building the CH
//   2. custom verify callback     -> SSL_reality_verify_certificate() on the
//                                    leaf, which checks the HMAC-overwritten
//                                    certificate signature.

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/curve25519.h>
#include <openssl/ssl.h>

#include "reality_common.h"

namespace {

enum ssl_verify_result_t RealityVerify(SSL *ssl, uint8_t *out_alert) {
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
  fprintf(stderr, "[client] REALITY certificate check failed\n");
  *out_alert = SSL_AD_BAD_CERTIFICATE;
  return ssl_verify_invalid;
}

int ConnectTcp(const char *host, int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (fd < 0 || connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) !=
                    0) {
    return -1;
  }
  return fd;
}

}  // namespace

int main(int argc, char **argv) {
  using namespace lwreality;
  if (argc < 4) {
    fprintf(stderr,
            "usage: %s <port> <public-key-hex> <short-id-hex> [message]\n",
            argv[0]);
    return 1;
  }
  const int port = atoi(argv[1]);
  std::vector<uint8_t> public_key;
  std::vector<uint8_t> short_id;
  if (!HexDecode(argv[2], &public_key) || public_key.size() != 32 ||
      !HexDecode(argv[3], &short_id) || short_id.size() > 8) {
    fprintf(stderr, "bad key/short id\n");
    return 1;
  }
  uint8_t short_id_padded[8] = {0};
  memcpy(short_id_padded, short_id.data(), short_id.size());

  const int fd = ConnectTcp("127.0.0.1", port);
  if (fd < 0) {
    perror("connect");
    return 1;
  }
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_client_method()));
  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_custom_verify(ctx.get(), SSL_VERIFY_PEER, RealityVerify);
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  if (!SSL_set_tlsext_host_name(ssl.get(), "mirror.test") ||
      !SSL_set1_reality_config(ssl.get(), public_key.data(), short_id_padded)) {
    fprintf(stderr, "reality config failed\n");
    return 1;
  }
  BIO *bio = BIO_new_socket(fd, BIO_CLOSE);
  SSL_set_bio(ssl.get(), bio, bio);
  SSL_set_connect_state(ssl.get());
  if (SSL_do_handshake(ssl.get()) != 1) {
    fprintf(stderr, "[client] handshake failed\n");
    ERR_print_errors_fp(stderr);
    return 1;
  }
  const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl.get());
  fprintf(stderr, "[client] handshake ok: %s / %s\n", SSL_get_version(ssl.get()),
          cipher != nullptr ? SSL_CIPHER_get_name(cipher) : "?");
  const char *message = argc > 4 ? argv[4] : "hello from reality client";
  const size_t message_len = strlen(message);
  if (SSL_write(ssl.get(), message, message_len) !=
      static_cast<int>(message_len)) {
    fprintf(stderr, "[client] write failed\n");
    return 1;
  }
  char buf[4096];
  const int n = SSL_read(ssl.get(), buf, sizeof(buf));
  if (n <= 0) {
    fprintf(stderr, "[client] read failed\n");
    return 1;
  }
  fprintf(stderr, "[client] echoed back %d bytes: %.*s\n", n, n, buf);
  SSL_shutdown(ssl.get());
  return 0;
}
