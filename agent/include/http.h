#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>

// ---------------------------------------------------------------------------
// HTTP transport layer.
//
// http_post_raw        — plaintext POST (used only for /register handshake).
// http_post_encrypted  — AES-256 encrypted POST (all post-handshake traffic).
//
// All functions return 0 on success, -1 on failure.
// On success, *out_body / *out_plain is a heap-allocated buffer the caller must free().
// ---------------------------------------------------------------------------

// Plain HTTP POST. Used only for the /register key exchange.
int http_post_raw(const char *host, int port, const char *path,
                  const uint8_t *body, int body_len,
                  uint8_t **out_body, int *out_body_len);


int http_post_encrypted(const char *host, int port, const char *path,
                        const uint8_t *plain_data, int plain_len,
                        uint8_t **out_plain, int *out_plain_len);

#endif // HTTP_H