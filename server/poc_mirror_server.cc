// Minimal "real site" used by the PoCs: a TLS 1.3 server with a self-signed
// Ed25519 certificate that echoes whatever it receives. It plays the role of
// the mirror target that the REALITY front end dials to capture a ServerHello.

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "reality_common.h"

int main(int argc, char **argv) {
  using namespace lwreality;
  int port = argc > 1 ? atoi(argv[1]) : 8443;
  // The mirror plays an ordinary TLS 1.3 site: use a P-256 certificate so that
  // stock BoringSSL clients (which do not advertise Ed25519) can verify the
  // signature algorithm. See docs/report.md section 7.
  std::vector<uint8_t> der;
  EVP_PKEY *key = nullptr;
  if (!RealityMakeTestCert(&der, &key)) {
    fprintf(stderr, "cert failed\n");
    return 1;
  }
  const uint8_t *p = der.data();
  bssl::UniquePtr<X509> x509(d2i_X509(nullptr, &p, der.size()));
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_server_method()));
  if (x509 == nullptr || ctx == nullptr ||
      !SSL_CTX_use_certificate(ctx.get(), x509.get()) ||
      !SSL_CTX_use_PrivateKey(ctx.get(), key)) {
    fprintf(stderr, "ctx setup failed\n");
    return 1;
  }
  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0 ||
      listen(fd, 16) != 0) {
    perror("mirror listen");
    return 1;
  }
  fprintf(stderr, "mirror server on 127.0.0.1:%d (cert %zu bytes)\n", port,
          der.size());
  for (;;) {
    const int conn = accept(fd, nullptr, nullptr);
    if (conn < 0) {
      continue;
    }
    fprintf(stderr, "mirror: accepted connection\n");
    bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
    BIO *bio = BIO_new_socket(conn, BIO_CLOSE);
    SSL_set_bio(ssl.get(), bio, bio);
    SSL_set_accept_state(ssl.get());
    if (SSL_do_handshake(ssl.get()) == 1) {
      char buf[4096];
      for (;;) {
        const int n = SSL_read(ssl.get(), buf, sizeof(buf));
        if (n <= 0) {
          break;
        }
        if (SSL_write(ssl.get(), buf, n) != n) {
          break;
        }
      }
    }
  }
  return 0;
}
