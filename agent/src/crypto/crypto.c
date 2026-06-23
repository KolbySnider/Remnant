#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "crypto/crypto.h"
#include "crypto/ecdh.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

#define NONCE_LEN  12
#define TAG_LEN    16
#define KEY_LEN    32   /* AES-256 */

/**
 * @brief Open the BCrypt AES provider in GCM mode and import SESSION_KEY.
 *        pbKeyObject must stay alive for the lifetime of hKey;
 *        pass both to gcm_close_key() when done.
 * @param hAlg        Receives the algorithm provider handle.
 * @param hKey        Receives the symmetric key handle.
 * @param pbKeyObject Receives the key object backing buffer.
 * @return 0 on success, -1 on any BCrypt failure (all handles cleaned up).
 */
static int gcm_open_key(BCRYPT_ALG_HANDLE *hAlg,
                        BCRYPT_KEY_HANDLE *hKey,
                        PUCHAR            *pbKeyObject)
{
    NTSTATUS s;
    DWORD    cbObject = 0, cbResult = 0;

    *hAlg = NULL; *hKey = NULL; *pbKeyObject = NULL;

    s = BCryptOpenAlgorithmProvider(hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(s)) goto fail;

    /* Switch chaining mode BEFORE generating the key handle. */
    s = BCryptSetProperty(*hAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(s)) goto fail;

    s = BCryptGetProperty(*hAlg, BCRYPT_OBJECT_LENGTH,
                          (PUCHAR)&cbObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(s) || cbObject == 0) goto fail;

    *pbKeyObject = (PUCHAR)malloc(cbObject);
    if (!*pbKeyObject) goto fail;

    s = BCryptGenerateSymmetricKey(*hAlg, hKey,
                                    *pbKeyObject, cbObject,
                                    (PUCHAR)SESSION_KEY, KEY_LEN, 0);
    if (!NT_SUCCESS(s)) goto fail;

    return 0;

fail:
    if (*hKey)        { BCryptDestroyKey(*hKey); *hKey = NULL; }
    if (*pbKeyObject) { free(*pbKeyObject);      *pbKeyObject = NULL; }
    if (*hAlg)        { BCryptCloseAlgorithmProvider(*hAlg, 0); *hAlg = NULL; }
    return -1;
}

/**
 * @param hAlg        Algorithm provider handle from gcm_open_key().
 * @param hKey        Symmetric key handle from gcm_open_key().
 * @param pbKeyObject Key object backing buffer from gcm_open_key().
 */
static void gcm_close_key(BCRYPT_ALG_HANDLE hAlg,
                          BCRYPT_KEY_HANDLE hKey,
                          PUCHAR            pbKeyObject)
{
    if (hKey)        BCryptDestroyKey(hKey);
    if (pbKeyObject) { SecureZeroMemory(pbKeyObject, 1); free(pbKeyObject); }
    if (hAlg)        BCryptCloseAlgorithmProvider(hAlg, 0);
}

uint8_t *aead_encrypt(const uint8_t *plaintext, size_t plain_len, size_t *out_len)
{
    if (!out_len) return NULL;
    *out_len = 0;
    if (plain_len > 0 && !plaintext) return NULL;

    BCRYPT_ALG_HANDLE hAlg        = NULL;
    BCRYPT_KEY_HANDLE hKey        = NULL;
    PUCHAR            pbKeyObject = NULL;
    uint8_t          *out         = NULL;

    if (gcm_open_key(&hAlg, &hKey, &pbKeyObject) != 0) return NULL;

    size_t total = NONCE_LEN + plain_len + TAG_LEN;
    out = (uint8_t *)malloc(total ? total : 1);
    if (!out) goto cleanup;

    gen_random_bytes(out, NONCE_LEN);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = out;
    authInfo.cbNonce = NONCE_LEN;
    authInfo.pbTag   = out + NONCE_LEN + plain_len;
    authInfo.cbTag   = TAG_LEN;

    ULONG    cbCipher = 0;
    NTSTATUS s = BCryptEncrypt(hKey,
                                (PUCHAR)plaintext, (ULONG)plain_len,
                                &authInfo,
                                NULL, 0,
                                out + NONCE_LEN, (ULONG)plain_len,
                                &cbCipher, 0);
    if (!NT_SUCCESS(s) || cbCipher != (ULONG)plain_len) {
        free(out); out = NULL;
        goto cleanup;
    }

    *out_len = total;

cleanup:
    gcm_close_key(hAlg, hKey, pbKeyObject);
    return out;
}

uint8_t *aead_decrypt(const uint8_t *encrypted, size_t enc_len, size_t *out_len)
{
    if (!out_len) return NULL;
    *out_len = 0;
    if (!encrypted || enc_len < NONCE_LEN + TAG_LEN) return NULL;

    size_t cipher_len = enc_len - NONCE_LEN - TAG_LEN;

    BCRYPT_ALG_HANDLE hAlg        = NULL;
    BCRYPT_KEY_HANDLE hKey        = NULL;
    PUCHAR            pbKeyObject = NULL;
    uint8_t          *plain       = NULL;

    if (gcm_open_key(&hAlg, &hKey, &pbKeyObject) != 0) return NULL;

    /* +1 so callers can use the buffer as a C string without copying */
    plain = (uint8_t *)malloc(cipher_len + 1);
    if (!plain) goto cleanup;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)encrypted;
    authInfo.cbNonce = NONCE_LEN;
    authInfo.pbTag   = (PUCHAR)(encrypted + NONCE_LEN + cipher_len);
    authInfo.cbTag   = TAG_LEN;

    ULONG    cbPlain = 0;
    NTSTATUS s = BCryptDecrypt(hKey,
                                (PUCHAR)(encrypted + NONCE_LEN), (ULONG)cipher_len,
                                &authInfo,
                                NULL, 0,
                                plain, (ULONG)cipher_len,
                                &cbPlain, 0);

    if (!NT_SUCCESS(s) || cbPlain != (ULONG)cipher_len) {
#ifdef DEBUG
        fprintf(stderr, "[!] AES-GCM verify failed (NTSTATUS 0x%08lX)\n",
                (unsigned long)s);
#endif
        free(plain); plain = NULL;
        goto cleanup;
    }

    plain[cipher_len] = '\0';
    *out_len = cipher_len;

cleanup:
    gcm_close_key(hAlg, hKey, pbKeyObject);
    return plain;
}
