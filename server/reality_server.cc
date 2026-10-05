// Lightweight REALITY front end.
//
// Layout, following https://blog.sam1314.com/posts/c65526af.html :
//
//   :443  this process
//           |-- recv(MSG_PEEK) the ClientHello, decide with the same stateless
//           |   authentication function that the TLS layer uses
//           |-- authenticated   -> REALITY TLS (certificate callback suspends,
//           |                       the ServerHello is mirrored from the real
//           |                       target, then the handshake resumes)
//           `-- anything else   -> transparent TCP proxy to the target
//
// The ClientHello is peeked, never drained, so both paths still see the
// complete original bytes.

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "reality_common.h"

namespace lwreality {
namespace {

constexpr size_t kPeekSize = 4096;

struct ServerOptions {
  std::string listen_host = "0.0.0.0";
  int listen_port = 443;
  std::string target_host;
  int target_port = 443;
  // Optional plaintext backend (e.g. a naive/h2 endpoint). When empty, the
  // REALITY connection echoes.
  std::string backend_host;
  int backend_port = 0;
  RealityConfig config;
};

int ConnectTcp(const std::string &host, int port) {
  addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo *res = nullptr;
  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);
  if (getaddrinfo(host.c_str(), port_str, &hints, &res) != 0) {
    return -1;
  }
  int fd = -1;
  for (addrinfo *ai = res; ai != nullptr; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) {
      continue;
    }
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
      break;
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

void Splice(int a, int b) {
  pollfd fds[2] = {{a, POLLIN, 0}, {b, POLLIN, 0}};
  uint8_t buf[16384];
  while (poll(fds, 2, -1) > 0) {
    for (int i = 0; i < 2; i++) {
      if ((fds[i].revents & (POLLIN | POLLHUP)) == 0) {
        continue;
      }
      const int from = fds[i].fd;
      const int to = i == 0 ? b : a;
      const ssize_t n = read(from, buf, sizeof(buf));
      if (n <= 0) {
        shutdown(a, SHUT_WR);
        shutdown(b, SHUT_WR);
        return;
      }
      ssize_t written = 0;
      while (written < n) {
        const ssize_t w = write(to, buf + written, n - written);
        if (w <= 0) {
          return;
        }
        written += w;
      }
    }
  }
}

std::string GroupNameFor(uint16_t group) {
  switch (group) {
    case 0x001d:
      return "X25519";
    case 0x11ec:
      return "X25519MLKEM768";
    case 0x0017:
      return "P-256";
    case 0x0018:
      return "P-384";
    case 0x0019:
      return "P-521";
    case 0x001e:
      return "X448";
    default:
      return "X25519";
  }
}

struct CaptureState {
  std::vector<uint8_t> server_hello;
  bool saw_hello_retry_request = false;
};

// The special random value that marks a HelloRetryRequest (RFC 8446, 4.1.3).
const uint8_t kHelloRetryRequestRandom[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
    0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
    0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

void MirrorMessageCallback(int write_p, int /*version*/, int content_type,
                           const void *buf, size_t len, SSL * /*ssl*/,
                           void *arg) {
  auto *capture = static_cast<CaptureState *>(arg);
  if (capture == nullptr || write_p != 0 ||
      content_type != SSL3_RT_HANDSHAKE || len < 1) {
    return;
  }
  const uint8_t *p = static_cast<const uint8_t *>(buf);
  if (p[0] != SSL3_MT_SERVER_HELLO || len < 38) {
    return;
  }
  if (memcmp(p + 6, kHelloRetryRequestRandom, 32) == 0) {
    capture->saw_hello_retry_request = true;
    return;
  }
  if (capture->server_hello.empty()) {
    capture->server_hello.assign(p, p + len);
  }
}

// Dials the real target and captures the ServerHello it returns right now.
// The group must be the one the client-facing handshake will negotiate (blog
// section 4.3), so it is placed first in the mirror connection's group list.
bool DialMirrorAndCapture(const ServerOptions &options, uint16_t group,
                          std::vector<uint8_t> *out) {
  const int fd = ConnectTcp(options.target_host, options.target_port);
  if (fd < 0) {
    return false;
  }
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_client_method()));
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  CaptureState capture;
  bool ok = false;
  if (ctx == nullptr || ssl == nullptr) {
    close(fd);
    return false;
  }
  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
  // No tickets => no pre_shared_key offer => the mirrored ServerHello cannot
  // select a PSK we did not negotiate.
  SSL_CTX_set_options(ctx.get(), SSL_OP_NO_TICKET);
  if (!SSL_set_tlsext_host_name(ssl.get(), options.target_host.c_str())) {
    close(fd);
    return false;
  }
  std::string groups = GroupNameFor(group);
  if (group != 0x001d) {
    groups += ":X25519";
  }
  if (!SSL_set1_groups_list(ssl.get(), groups.c_str())) {
    fprintf(stderr, "reality: mirror group list '%s' rejected\n",
            groups.c_str());
  }
  SSL_set_msg_callback(ssl.get(), MirrorMessageCallback);
  SSL_set_msg_callback_arg(ssl.get(), &capture);
  BIO *bio = BIO_new_socket(fd, BIO_CLOSE);
  SSL_set_bio(ssl.get(), bio, bio);
  SSL_set_connect_state(ssl.get());
  // Drive the mirror handshake to completion (or until the ServerHello has
  // been captured), tolerating a slightly slower peer.
  int rv = SSL_do_handshake(ssl.get());
  for (int i = 0; i < 20 && rv != 1 && capture.server_hello.empty(); i++) {
    const int err = SSL_get_error(ssl.get(), rv);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      break;
    }
    pollfd pfd = {fd, static_cast<short>(err == SSL_ERROR_WANT_READ ? POLLIN
                                                                     : POLLOUT),
                  0};
    if (poll(&pfd, 1, 2000) <= 0) {
      break;
    }
    rv = SSL_do_handshake(ssl.get());
  }
  if (capture.server_hello.empty()) {
    fprintf(stderr,
            "reality: mirror dial failed (rv=%d, err=%d, hrr=%d, groups=%s)\n",
            rv, SSL_get_error(ssl.get(), rv),
            capture.saw_hello_retry_request ? 1 : 0, groups.c_str());
  }
  if (!capture.saw_hello_retry_request && !capture.server_hello.empty()) {
    *out = std::move(capture.server_hello);
    ok = true;
  }
  return ok;
}

// Extracts the cipher suite from a ServerHello handshake message.
bool ServerHelloCipher(const std::vector<uint8_t> &sh, uint16_t *out) {
  CBS cbs(bssl::Span<const uint8_t>(sh.data(), sh.size())), body, random, session_id;
  uint8_t type;
  uint32_t body_len;
  if (!CBS_get_u8(&cbs, &type) || type != SSL3_MT_SERVER_HELLO ||
      !CBS_get_u24(&cbs, &body_len) || !CBS_get_bytes(&cbs, &body, body_len) ||
      !CBS_get_u16(&body, out) /* legacy_version */ ||
      !CBS_get_bytes(&body, &random, 32) ||
      !CBS_get_u8_length_prefixed(&body, &session_id) ||
      !CBS_get_u16(&body, out)) {
    return false;
  }
  return true;
}

struct ConnState {
  const ServerOptions *options = nullptr;
  RealityAuthResult auth;
  bool mirror_attempted = false;
  bool mirror_ok = false;
  std::vector<uint8_t> mirror_server_hello;
};

enum ssl_select_cert_result_t SelectCertificateCallback(
    const SSL_CLIENT_HELLO *client_hello) {
  SSL *ssl = client_hello->ssl;
  auto *state = static_cast<ConnState *>(SSL_get_app_data(ssl));
  if (state == nullptr) {
    return ssl_select_cert_error;
  }
  if (!state->mirror_attempted) {
    // First call: authenticate. The same function ran in the L4 peek path.
    RealityAuthResult auth;
    if (!RealityAuthDecide(client_hello, state->options->config, &auth)) {
      return ssl_select_cert_error;
    }
    state->auth = std::move(auth);
    // Install the per-connection temporary certificate. Its signature field
    // carries HMAC-SHA512(AuthKey, ed25519_public_key), which is how a REALITY
    // client authenticates this server.
    std::vector<uint8_t> der;
    if (!RealityMakeTempCert(state->auth.auth_key, &der)) {
      return ssl_select_cert_error;
    }
    const uint8_t *p = der.data();
    bssl::UniquePtr<X509> x509(d2i_X509(nullptr, &p, der.size()));
    if (x509 == nullptr || !SSL_use_certificate(ssl, x509.get()) ||
        !SSL_use_PrivateKey(ssl, RealityIdentityPrivateKey())) {
      return ssl_select_cert_error;
    }
    state->mirror_attempted = true;
    // Suspend: the caller dials the mirror while the handshake is paused.
    return ssl_select_cert_retry;
  }
  return ssl_select_cert_success;
}

int ServerHelloMirrorCallback(SSL *ssl, const uint8_t **out, size_t *out_len) {
  auto *state = static_cast<ConnState *>(SSL_get_app_data(ssl));
  if (state == nullptr || !state->mirror_ok) {
    return 0;
  }
  // Adopt the mirror's cipher suite only when the client offered it (blog
  // section 2, seam three).
  uint16_t cipher = 0;
  if (!ServerHelloCipher(state->mirror_server_hello, &cipher)) {
    return 0;
  }
  bool offered = false;
  for (uint16_t c : state->auth.client_ciphers) {
    offered = offered || c == cipher;
  }
  if (!offered) {
    return 0;
  }
  *out = state->mirror_server_hello.data();
  *out_len = state->mirror_server_hello.size();
  return 1;
}

// L4 decision: peek the ClientHello and run the same authentication function
// through a parse-only BoringSSL instance. Nothing is consumed, so the winning
// path still reads the complete ClientHello.
struct ParseState {
  const RealityConfig *config = nullptr;
  RealityAuthResult auth;
};

enum ssl_select_cert_result_t ParseOnlyCallback(
    const SSL_CLIENT_HELLO *client_hello) {
  auto *state = static_cast<ParseState *>(SSL_get_app_data(client_hello->ssl));
  if (state == nullptr ||
      !RealityAuthDecide(client_hello, *state->config, &state->auth)) {
    return ssl_select_cert_error;
  }
  // Abort the parse-only handshake; no bytes ever reach the socket.
  return ssl_select_cert_error;
}

bool L4Authenticate(int fd, const ServerOptions &options,
                    RealityAuthResult *out) {
  uint8_t buf[kPeekSize];
  const ssize_t n = recv(fd, buf, sizeof(buf), MSG_PEEK);
  if (n <= 0) {
    return false;
  }
  static SSL_CTX *ctx = [] {
    SSL_CTX *c = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_select_certificate_cb(c, ParseOnlyCallback);
    return c;
  }();
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx));
  BIO *in = BIO_new(BIO_s_mem());
  BIO *out_bio = BIO_new(BIO_s_mem());
  if (ssl == nullptr || in == nullptr || out_bio == nullptr) {
    return false;
  }
  BIO_write(in, buf, n);
  SSL_set_bio(ssl.get(), in, out_bio);
  SSL_set_accept_state(ssl.get());
  ParseState state;
  state.config = &options.config;
  SSL_set_app_data(ssl.get(), &state);
  SSL_do_handshake(ssl.get());
  if (!state.auth.ok) {
    return false;
  }
  *out = std::move(state.auth);
  return true;
}

void RunRealityConnection(int fd, const ServerOptions &options,
                          RealityAuthResult auth) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_server_method()));
  if (ctx == nullptr) {
    close(fd);
    return;
  }
  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_select_certificate_cb(ctx.get(), SelectCertificateCallback);
  SSL_CTX_set_reality_serverhello_cb(ctx.get(), ServerHelloMirrorCallback);
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  if (ssl == nullptr) {
    close(fd);
    return;
  }
  ConnState state;
  state.options = &options;
  state.auth = std::move(auth);
  SSL_set_app_data(ssl.get(), &state);
  BIO *bio = BIO_new_socket(fd, BIO_CLOSE);
  SSL_set_bio(ssl.get(), bio, bio);
  SSL_set_accept_state(ssl.get());

  int rv = SSL_do_handshake(ssl.get());
  if (SSL_get_error(ssl.get(), rv) == SSL_ERROR_PENDING_CERTIFICATE) {
    // Suspension window: dial the mirror, capture its ServerHello, then resume.
    state.mirror_ok = DialMirrorAndCapture(options, state.auth.first_group,
                                           &state.mirror_server_hello);
    rv = SSL_do_handshake(ssl.get());
  }
  if (rv != 1) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "reality: handshake failed\n");
    return;
  }
  fprintf(stderr, "reality: handshake ok (mirrored ServerHello: %s, %zu bytes)\n",
          state.mirror_ok ? "yes" : "no", state.mirror_server_hello.size());

  if (!options.backend_host.empty()) {
    const int backend = ConnectTcp(options.backend_host, options.backend_port);
    if (backend < 0) {
      return;
    }
    // Plaintext <-> backend.
    pollfd fds[2] = {{fd, POLLIN, 0}, {backend, POLLIN, 0}};
    uint8_t buf[16384];
    while (poll(fds, 2, -1) > 0) {
      for (int i = 0; i < 2; i++) {
        if ((fds[i].revents & (POLLIN | POLLHUP)) == 0) {
          continue;
        }
        if (i == 0) {
          const int n = SSL_read(ssl.get(), buf, sizeof(buf));
          if (n <= 0) {
            return;
          }
          if (write(backend, buf, n) != n) {
            return;
          }
        } else {
          const ssize_t n = read(backend, buf, sizeof(buf));
          if (n <= 0) {
            return;
          }
          if (SSL_write(ssl.get(), buf, n) != n) {
            return;
          }
        }
        break;
      }
    }
    close(backend);
    return;
  }

  // No backend: echo the decrypted stream back.
  uint8_t buf[16384];
  for (;;) {
    const int n = SSL_read(ssl.get(), buf, sizeof(buf));
    if (n <= 0) {
      return;
    }
    if (SSL_write(ssl.get(), buf, n) != n) {
      return;
    }
  }
}

void HandleConnection(int fd, const ServerOptions &options) {
  RealityAuthResult auth;
  if (L4Authenticate(fd, options, &auth)) {
    RunRealityConnection(fd, options, std::move(auth));
    return;
  }
  // Transparent fallback: the ClientHello is still in the socket buffer
  // because the peek never consumed it, so the target sees the original bytes.
  const int target = ConnectTcp(options.target_host, options.target_port);
  if (target < 0) {
    close(fd);
    return;
  }
  Splice(fd, target);
  close(target);
  close(fd);
}

int ListenOn(const std::string &host, int port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
  if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0 ||
      listen(fd, 128) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

bool ParseArgs(int argc, char **argv, ServerOptions *options) {
  std::string private_key_hex;
  std::string short_id_hex;
  for (int i = 1; i < argc; i++) {
    const std::string arg = argv[i];
    auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
    if (arg == "--listen") {
      const std::string value = next();
      const size_t colon = value.find(':');
      options->listen_host = value.substr(0, colon);
      options->listen_port = atoi(value.substr(colon + 1).c_str());
    } else if (arg == "--target") {
      const std::string value = next();
      const size_t colon = value.find(':');
      options->target_host = value.substr(0, colon);
      options->target_port = atoi(value.substr(colon + 1).c_str());
    } else if (arg == "--backend") {
      const std::string value = next();
      const size_t colon = value.find(':');
      options->backend_host = value.substr(0, colon);
      options->backend_port = atoi(value.substr(colon + 1).c_str());
    } else if (arg == "--private-key") {
      private_key_hex = next();
    } else if (arg == "--short-id") {
      short_id_hex = next();
    } else {
      fprintf(stderr, "unknown argument: %s\n", arg.c_str());
      return false;
    }
  }
  std::vector<uint8_t> key;
  std::vector<uint8_t> short_id;
  if (options->target_host.empty() || !HexDecode(private_key_hex, &key) ||
      key.size() != 32 || !HexDecode(short_id_hex, &short_id) ||
      short_id.size() > 8) {
    fprintf(stderr,
            "usage: %s --listen 0.0.0.0:443 --target host:443 "
            "--private-key <64 hex> --short-id <hex> [--backend host:port]\n",
            argv[0]);
    return false;
  }
  memcpy(options->config.private_key, key.data(), 32);
  memcpy(options->config.short_id, short_id.data(), short_id.size());
  return true;
}

}  // namespace
}  // namespace lwreality

int main(int argc, char **argv) {
  using namespace lwreality;
  ServerOptions options;
  if (!ParseArgs(argc, argv, &options) || !RealityInitIdentity()) {
    return 1;
  }
  const int listen_fd = ListenOn(options.listen_host, options.listen_port);
  if (listen_fd < 0) {
    perror("listen");
    return 1;
  }
  fprintf(stderr, "reality front end listening on %s:%d -> %s:%d\n",
          options.listen_host.c_str(), options.listen_port,
          options.target_host.c_str(), options.target_port);
  for (;;) {
    const int fd = accept(listen_fd, nullptr, nullptr);
    if (fd < 0) {
      continue;
    }
    std::thread(HandleConnection, fd, options).detach();
  }
  return 0;
}
