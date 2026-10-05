// Lightweight REALITY: shared pieces between the L4 front end, the REALITY TLS
// server and the in-process PoCs.
//
// Everything here mirrors the mechanism described in
// https://blog.sam1314.com/posts/c65526af.html :
//   - authentication lives in the ClientHello's legacy_session_id
//     (X25519 -> HKDF-SHA256 -> AES-256-GCM),
//   - the same stateless function decides in the TLS certificate callback and
//     in the L4 peek path,
//   - the temporary certificate's signature field carries
//     HMAC-SHA512(AuthKey, ed25519_public_key) (XTLS/REALITY semantics).

#ifndef LIGHTWEIGHT_REALITY_REALITY_COMMON_H_
#define LIGHTWEIGHT_REALITY_REALITY_COMMON_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/ssl.h>

namespace lwreality {

// REALITY client version bytes, matching XTLS/REALITY and the naivereal client
// (1.0.0). Carried in the first three bytes of the sealed session id.
inline constexpr uint8_t kClientVersion[3] = {1, 0, 0};

// Offset of the legacy_session_id contents inside a ClientHello handshake
// message: 4-byte handshake header + 2-byte legacy_version + 32-byte random,
// followed by the one-byte session-id length prefix.
inline constexpr size_t kSessionIdOffset = 39;
inline constexpr size_t kSessionIdLength = 32;

inline constexpr uint16_t kGroupX25519 = 0x001d;
inline constexpr uint16_t kGroupX25519Mlkem768 = 0x11ec;
inline constexpr uint16_t kExtensionKeyShare = 51;

struct RealityConfig {
  // Static X25519 private key of this REALITY server (the public half is what
  // clients are configured with).
  uint8_t private_key[32] = {0};
  uint8_t short_id[8] = {0};
  // Accepted clock skew for the timestamp in the sealed session id.
  int max_time_diff_seconds = 30;
};

// Result of a successful authentication, plus everything the caller needs to
// continue: the derived AuthKey (for the temporary certificate), the client's
// first offered key share group (what the mirror must be dialed with) and the
// raw ClientHello bytes.
struct RealityAuthResult {
  bool ok = false;
  uint8_t auth_key[32] = {0};
  uint8_t client_random[32] = {0};
  // First key_share entry offered by the client: what the mirror site must be
  // asked for (blog section 4.3).
  uint16_t first_group = 0;
  std::vector<uint8_t> first_key_share;
  // The X25519 key share used for the REALITY ECDH. With a hybrid first share
  // (X25519MLKEM768) this is the client's separate X25519 share.
  bool has_x25519 = false;
  uint8_t x25519_key_share[32] = {0};
  // Raw ClientHello (copy: the SSL_CLIENT_HELLO is only valid during the
  // callback) and the offered cipher suites.
  std::vector<uint8_t> client_hello;
  std::vector<uint16_t> client_ciphers;
  std::vector<uint8_t> session_id;
};

// RealityAuthDecide is the stateless authentication function. It is called both
// from the TLS certificate-selection callback and from the L4 MSG_PEEK path;
// it only reads |ch| and |config|.
bool RealityAuthDecide(const SSL_CLIENT_HELLO *ch, const RealityConfig &config,
                       RealityAuthResult *out);

// Process-wide Ed25519 identity for the temporary certificate.
bool RealityInitIdentity();
const uint8_t *RealityIdentityPublicKey();
EVP_PKEY *RealityIdentityPrivateKey();

// RealityMakeTempCert writes a DER certificate for the process identity whose
// signature field is overwritten with HMAC-SHA512(auth_key, ed25519_pub),
// exactly like XTLS/REALITY does.
bool RealityMakeTempCert(const uint8_t auth_key[32], std::vector<uint8_t> *out);

// Parses a ClientHello's key_share extension. If |want_group| is zero, returns
// the first entry; otherwise the entry for |want_group|. Returns false when
// there is no such entry.
bool FindKeyShare(const SSL_CLIENT_HELLO *ch, uint16_t want_group,
                  uint16_t *group_out, const uint8_t **key_out,
                  size_t *key_len_out);

bool HexDecode(const std::string &hex, std::vector<uint8_t> *out);

// RealityMakeTestCert builds a throwaway ECDSA P-256 self-signed certificate,
// used by the PoCs for the mirror ("real site") endpoint. Returns the DER and
// the matching private key.
bool RealityMakeTestCert(std::vector<uint8_t> *der_out, EVP_PKEY **key_out);

}  // namespace lwreality

#endif  // LIGHTWEIGHT_REALITY_REALITY_COMMON_H_
