#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 AEAD (RFC 8439) — self-contained, no BCrypt required.
//
// SESSION_KEY is defined in ecdh.c and written once during ECDH registration.
// Both functions below read it via the extern declared in ecdh.h.
//
// Wire format: [12-byte nonce][ciphertext][16-byte Poly1305 tag]
// ---------------------------------------------------------------------------

// Encrypt plaintext with the current SESSION_KEY.
// Returns a heap-allocated buffer [nonce(12) | ciphertext(len) | tag(16)].
// *out_len is set to 12 + plain_len + 16. Caller must free().
// Returns NULL on allocation failure.
uint8_t *chacha20poly1305_encrypt(const uint8_t *plaintext, size_t plain_len,
                                   size_t *out_len);

// Decrypt and authenticate an encrypted buffer produced by chacha20poly1305_encrypt.
// Returns a heap-allocated, null-terminated plaintext buffer.
// *out_len is set to the plaintext length (excluding the null terminator).
// Returns NULL if the Poly1305 tag does not verify or on allocation failure.
uint8_t *chacha20poly1305_decrypt(const uint8_t *encrypted, size_t enc_len,
                                   size_t *out_len);

#endif // CRYPTO_H