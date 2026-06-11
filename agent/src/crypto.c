#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "crypto.h"
#include "ecdh.h"   /* for SESSION_KEY[32] and gen_random_bytes() */

/* BCrypt status check helper.  Anything other than STATUS_SUCCESS (0) is a
 * failure; the NTSTATUS itself is mostly only useful for logging. */
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

#define NONCE_LEN  12
#define TAG_LEN    16
#define KEY_LEN    32   /* AES-256 */

/* ---------------------------------------------------------------------------
 * gcm_open_key — internal helper.
 *
 * Opens the AES provider, switches it to GCM mode, and imports SESSION_KEY
 * as an AES-256 symmetric key.  Returns 0 on success; on failure all
 * resources are freed and *hAlg / *hKey / *pbKeyObject are zeroed.
 *
 * Per BCrypt's API contract the caller must keep pbKeyObject alive for the
 * lifetime of hKey — it's the heap backing for the key handle's internal
 * state.  gcm_close_key() frees both together.
 * --------------------------------------------------------------------------- */
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

    /* Ask BCrypt how large the per-key state buffer needs to be. */
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

static void gcm_close_key(BCRYPT_ALG_HANDLE hAlg,
                          BCRYPT_KEY_HANDLE hKey,
                          PUCHAR            pbKeyObject)
{
    if (hKey)        BCryptDestroyKey(hKey);
    if (pbKeyObject) { SecureZeroMemory(pbKeyObject, 1); free(pbKeyObject); }
    if (hAlg)        BCryptCloseAlgorithmProvider(hAlg, 0);
}

/* ---------------------------------------------------------------------------
 * aead_encrypt
 * --------------------------------------------------------------------------- */
uint8_t *aead_encrypt(const uint8_t *plaintext, size_t plain_len,
                      size_t *out_len)
{
    if (!out_len) return NULL;
    *out_len = 0;

    /* Allow plain_len == 0 (empty body checkin uses this). */
    if (plain_len > 0 && !plaintext) return NULL;

    BCRYPT_ALG_HANDLE hAlg        = NULL;
    BCRYPT_KEY_HANDLE hKey        = NULL;
    PUCHAR            pbKeyObject = NULL;
    uint8_t          *out         = NULL;

    if (gcm_open_key(&hAlg, &hKey, &pbKeyObject) != 0) return NULL;

    size_t total = NONCE_LEN + plain_len + TAG_LEN;
    out = (uint8_t *)malloc(total ? total : 1);
    if (!out) goto cleanup;

    /* Fresh 96-bit nonce.  BCryptGenRandom under the hood. */
    gen_random_bytes(out, NONCE_LEN);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = out;                    /* first 12 bytes of output */
    authInfo.cbNonce = NONCE_LEN;
    authInfo.pbTag   = out + NONCE_LEN + plain_len;  /* last 16 bytes  */
    authInfo.cbTag   = TAG_LEN;
    /* No AAD: pbAuthData / cbAuthData stay NULL / 0 from the init macro. */

    ULONG    cbCipher = 0;
    NTSTATUS s = BCryptEncrypt(hKey,
                                (PUCHAR)plaintext, (ULONG)plain_len,
                                &authInfo,
                                NULL, 0,                  /* no IV chaining state */
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

/* ---------------------------------------------------------------------------
 * aead_decrypt
 * --------------------------------------------------------------------------- */
uint8_t *aead_decrypt(const uint8_t *encrypted, size_t enc_len,
                      size_t *out_len)
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

    /* +1 for the NUL terminator we append for convenience.  Caller can
     * pass the buffer straight to strlen/printf without copying. */
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

    /* STATUS_AUTH_TAG_MISMATCH (0xC000A002) — silent drop, the caller
     * should treat NULL as "bad packet" and not log the key. */
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