// Prints a fresh X25519 key pair for the PoCs: private key, then public key,
// both hex, one per line.
#include <stdio.h>
#include <openssl/curve25519.h>

int main() {
  uint8_t public_key[32], private_key[32];
  X25519_keypair(public_key, private_key);
  for (int i = 0; i < 32; i++) printf("%02x", private_key[i]);
  printf("\n");
  for (int i = 0; i < 32; i++) printf("%02x", public_key[i]);
  printf("\n");
  return 0;
}
