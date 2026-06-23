#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Encrypt plaintext with SESSION_KEY using a fresh random nonce.
 *        Wire format: nonce(12) | ciphertext(plain_len) | tag(16).
 * @param plaintext Input buffer (may be NULL when plain_len == 0).
 * @param plain_len Input length in bytes.
 * @param out_len   Receives total output length (plain_len + 28).
 * @return Heap-allocated encrypted buffer, or NULL on failure. Caller must free().
 */
uint8_t *aead_encrypt(const uint8_t *plaintext, size_t plain_len, size_t *out_len);

/**
 * @brief Decrypt and authenticate a buffer produced by aead_encrypt.
 * @param encrypted Input buffer: nonce(12) | ciphertext | tag(16).
 * @param enc_len   Input length in bytes (minimum 28).
 * @param out_len   Receives plaintext length (excluding the appended NUL).
 * @return Heap-allocated NUL-terminated plaintext, or NULL if tag verification
 *         fails or allocation fails. Caller must free().
 */
uint8_t *aead_decrypt(const uint8_t *encrypted, size_t enc_len, size_t *out_len);

#endif /* CRYPTO_H */
