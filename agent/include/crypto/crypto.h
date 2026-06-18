#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* ---------------------------------------------------------------------------
 * AES-256-GCM AEAD via BCrypt (Windows CNG).
 *
 * SESSION_KEY is defined in ecdh.c and written once during ECDH registration
 * (SHA-256 of the ECDH shared secret).  Both functions below read it via the
 * extern declared in ecdh.h.
 *
 * Wire format: [12-byte nonce][ciphertext(N)][16-byte GCM tag]
 *
 * No AAD is authenticated.  The tag covers ciphertext only.
 * --------------------------------------------------------------------------- */

/* Encrypt with the current SESSION_KEY using a fresh random 96-bit nonce.
 * Returns a heap-allocated buffer [nonce(12) | ct(plain_len) | tag(16)].
 * *out_len is set to 12 + plain_len + 16.  Caller must free().
 * Returns NULL on allocation or BCrypt failure.
 */
uint8_t *aead_encrypt(const uint8_t *plaintext, size_t plain_len,
                      size_t *out_len);

/* Decrypt and authenticate a buffer produced by aead_encrypt.
 * Returns a heap-allocated, NUL-terminated plaintext buffer.
 * *out_len is set to the plaintext length (excluding the NUL).
 * Returns NULL if the GCM tag does not verify or on allocation failure.
 */
uint8_t *aead_decrypt(const uint8_t *encrypted, size_t enc_len,
                      size_t *out_len);

#endif /* CRYPTO_H */