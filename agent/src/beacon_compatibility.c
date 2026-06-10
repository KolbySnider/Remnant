/*
 * beacon_compatibility.c  –  Cobalt Strike 4.x BOF compatibility layer
 *                            (hardened)
 *
 * Hardening over v1
 * ─────────────────
 * [OUTBUF]  BeaconOutput/BeaconPrintf accumulate into an output buffer that
 *           is XOR-encrypted at rest.  A per-session 64-bit key is derived
 *           once at first use; the key is wiped when BeaconGetOutputData
 *           transfers ownership so the plaintext never persists.
 *
 * [CANARY]  Internal format buffer (BeaconFormatAlloc) is allocated with
 *           a 8-byte canary word at the end; BeaconFormatFree checks it and
 *           calls __debugbreak() / abort() on mismatch.
 *
 * [WIPE]    All format and output buffers are SecureZeroMemory'd on free.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#include "beacon_compatibility.h"

/* =========================================================================
 * Arch-specific process paths
 * ========================================================================= */
#define DEFAULTPROCESSNAME  "rundll32.exe"
#ifdef _WIN64
#  define X86PATH  "SysWOW64"
#  define X64PATH  "System32"
#else
#  define X86PATH  "System32"
#  define X64PATH  "sysnative"
#endif

/* =========================================================================
 * Internal-function dispatch table
 * =========================================================================
 * Slot 29 = __C_specific_handler, populated at runtime by the loader.
 * ========================================================================= */
unsigned char* InternalFunctions[30][2] = {
    { (unsigned char*)"BeaconDataParse",             (unsigned char*)BeaconDataParse             },
    { (unsigned char*)"BeaconDataInt",               (unsigned char*)BeaconDataInt               },
    { (unsigned char*)"BeaconDataShort",             (unsigned char*)BeaconDataShort             },
    { (unsigned char*)"BeaconDataLength",            (unsigned char*)BeaconDataLength            },
    { (unsigned char*)"BeaconDataExtract",           (unsigned char*)BeaconDataExtract           },
    { (unsigned char*)"BeaconFormatAlloc",           (unsigned char*)BeaconFormatAlloc           },
    { (unsigned char*)"BeaconFormatReset",           (unsigned char*)BeaconFormatReset           },
    { (unsigned char*)"BeaconFormatFree",            (unsigned char*)BeaconFormatFree            },
    { (unsigned char*)"BeaconFormatAppend",          (unsigned char*)BeaconFormatAppend          },
    { (unsigned char*)"BeaconFormatPrintf",          (unsigned char*)BeaconFormatPrintf          },
    { (unsigned char*)"BeaconFormatToString",        (unsigned char*)BeaconFormatToString        },
    { (unsigned char*)"BeaconFormatInt",             (unsigned char*)BeaconFormatInt             },
    { (unsigned char*)"BeaconPrintf",                (unsigned char*)BeaconPrintf                },
    { (unsigned char*)"BeaconOutput",                (unsigned char*)BeaconOutput                },
    { (unsigned char*)"BeaconUseToken",              (unsigned char*)BeaconUseToken              },
    { (unsigned char*)"BeaconRevertToken",           (unsigned char*)BeaconRevertToken           },
    { (unsigned char*)"BeaconIsAdmin",               (unsigned char*)BeaconIsAdmin               },
    { (unsigned char*)"BeaconGetSpawnTo",            (unsigned char*)BeaconGetSpawnTo            },
    { (unsigned char*)"BeaconSpawnTemporaryProcess", (unsigned char*)BeaconSpawnTemporaryProcess },
    { (unsigned char*)"BeaconInjectProcess",         (unsigned char*)BeaconInjectProcess         },
    { (unsigned char*)"BeaconInjectTemporaryProcess",(unsigned char*)BeaconInjectTemporaryProcess},
    { (unsigned char*)"BeaconCleanupProcess",        (unsigned char*)BeaconCleanupProcess        },
    { (unsigned char*)"toWideChar",                  (unsigned char*)toWideChar                  },
    { (unsigned char*)"LoadLibraryA",                (unsigned char*)LoadLibraryA                },
    { (unsigned char*)"GetProcAddress",              (unsigned char*)GetProcAddress              },
    { (unsigned char*)"GetModuleHandleA",            (unsigned char*)GetModuleHandleA            },
    { (unsigned char*)"FreeLibrary",                 (unsigned char*)FreeLibrary                 },
    { NULL, NULL },   /* reserved */
    { NULL, NULL },   /* reserved */
    { (unsigned char*)"__C_specific_handler", NULL } /* [29] – set at runtime */
};

/* =========================================================================
 * Output buffer – encrypted at rest
 * =========================================================================
 * Layout in heap: [enc bytes][plaintext length : uint32_t]
 * Only the byte content is encrypted; the length counter is kept plaintext
 * for cheap size queries without a decrypt round-trip.
 * ========================================================================= */
static char*    g_out_buf     = NULL;
static int      g_out_size    = 0;     /* plaintext bytes stored */
static int      g_out_offset  = 0;     /* write cursor           */
static uint64_t g_out_key     = 0;     /* per-session enc key    */
static LONG     g_out_key_init = 0;

/* xorshift64 keystream – same logic as COFFLoader.c */
static void out_xor(char* buf, int len, uint64_t key, int offset) {
    uint64_t ks = key;
    /* Fast-forward keystream to byte `offset` */
    for (int i = 0; i < offset; i++) {
        ks ^= ks >> 12; ks ^= ks << 25; ks ^= ks >> 27;
    }
    for (int i = 0; i < len; i++) {
        ks ^= ks >> 12; ks ^= ks << 25; ks ^= ks >> 27;
        buf[i] ^= (char)(ks & 0xFF);
    }
}

static void ensure_out_key(void) {
    if (InterlockedCompareExchange(&g_out_key_init, 1, 0) == 0) {
        LARGE_INTEGER li;
        QueryPerformanceCounter(&li);
        uint64_t x = (uint64_t)li.QuadPart ^ ((uint64_t)GetTickCount64() << 17);
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        g_out_key = x ? x : 0xA5A5A5A5A5A5A5A5ULL;
        InterlockedExchange(&g_out_key_init, 2);
    } else {
        while (InterlockedCompareExchange(&g_out_key_init, 2, 2) != 2)
            Sleep(0);
    }
}

/* Decrypt the buffer in-place from [start, start+len), append new bytes,
 * re-encrypt the whole thing.  This keeps the invariant that g_out_buf is
 * always ciphertext. */
static void out_append(const char* data, int len) {
    if (!data || len <= 0) return;
    ensure_out_key();

    char* tmp = (char*)realloc(g_out_buf, (size_t)(g_out_size + len + 1));
    if (!tmp) return;
    g_out_buf = tmp;

    /* Decrypt existing content */
    if (g_out_offset > 0)
        out_xor(g_out_buf, g_out_offset, g_out_key, 0);

    /* Append new plaintext */
    memcpy(g_out_buf + g_out_offset, data, (size_t)len);
    g_out_buf[g_out_offset + len] = '\0';
    g_out_size   += len;
    g_out_offset += len;

    /* Re-encrypt the whole buffer */
    out_xor(g_out_buf, g_out_offset, g_out_key, 0);
}

/* =========================================================================
 * Format-buffer canary
 * ========================================================================= */
#define FORMAT_CANARY_VALUE  UINT64_C(0xDEADBEEFCAFEBABE)
#define FORMAT_CANARY_SIZE   8

static void fmt_write_canary(formatp* f) {
    if (!f || !f->original) return;
    uint64_t c = FORMAT_CANARY_VALUE;
    memcpy(f->original + f->size, &c, FORMAT_CANARY_SIZE);
}

static bool fmt_check_canary(const formatp* f) {
    if (!f || !f->original) return true;
    uint64_t c = 0;
    memcpy(&c, f->original + f->size, FORMAT_CANARY_SIZE);
    return c == FORMAT_CANARY_VALUE;
}

/* =========================================================================
 * Endianness
 * ========================================================================= */
static uint32_t swap_endianess(uint32_t in) {
    uint32_t probe = 0xAABBCCDD;
    if (((unsigned char*)&probe)[0] == 0xDD)
        return ((in & 0x000000FFu) << 24) | ((in & 0x0000FF00u) <<  8)
             | ((in & 0x00FF0000u) >>  8) | ((in & 0xFF000000u) >> 24);
    return in;
}

/* =========================================================================
 * Data-parser API
 * ========================================================================= */
void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (!parser || !buffer || size < 4) return;
    parser->original = buffer;
    parser->buffer   = buffer + 4;
    parser->length   = size - 4;
    parser->size     = size - 4;
}

int BeaconDataInt(datap* parser) {
    if (!parser || parser->length < 4) return 0;
    int32_t v = 0;
    memcpy(&v, parser->buffer, 4);
    parser->buffer += 4; parser->length -= 4;
    return (int)v;
}

short BeaconDataShort(datap* parser) {
    if (!parser || parser->length < 2) return 0;
    int16_t v = 0;
    memcpy(&v, parser->buffer, 2);
    parser->buffer += 2; parser->length -= 2;
    return (short)v;
}

int BeaconDataLength(datap* parser) {
    return parser ? parser->length : 0;
}

char* BeaconDataExtract(datap* parser, int* size) {
    if (!parser || parser->length < 4) return NULL;
    uint32_t blen = 0;
    memcpy(&blen, parser->buffer, 4);
    parser->buffer += 4; parser->length -= 4;
    if ((int)blen > parser->length) return NULL;
    char* out = parser->buffer;
    parser->buffer += blen; parser->length -= (int)blen;
    if (size) *size = (int)blen;
    return out;
}

/* =========================================================================
 * Format API  (with canary)
 * ========================================================================= */
void BeaconFormatAlloc(formatp* format, int maxsz) {
    if (!format || maxsz <= 0) return;
    /* Allocate size + canary bytes */
    format->original = (char*)calloc((size_t)maxsz + FORMAT_CANARY_SIZE, 1);
    format->buffer   = format->original;
    format->length   = 0;
    format->size     = maxsz;
    fmt_write_canary(format);
}

void BeaconFormatReset(formatp* format) {
    if (!format || !format->original) return;
    if (!fmt_check_canary(format)) { __debugbreak(); return; }
    SecureZeroMemory(format->original, (size_t)format->size);
    fmt_write_canary(format);   /* restore canary after wipe */
    format->buffer = format->original;
    format->length = 0;
}

void BeaconFormatFree(formatp* format) {
    if (!format) return;
    if (format->original) {
        if (!fmt_check_canary(format)) __debugbreak();
        SecureZeroMemory(format->original,
                         (size_t)format->size + FORMAT_CANARY_SIZE);
        free(format->original);
        format->original = NULL;
    }
    format->buffer = NULL;
    format->length = 0;
    format->size   = 0;
}

void BeaconFormatAppend(formatp* format, char* text, int len) {
    if (!format || !text || len <= 0) return;
    if (!fmt_check_canary(format)) { __debugbreak(); return; }
    if (format->length + len > format->size) return;
    memcpy(format->buffer, text, (size_t)len);
    format->buffer += len;
    format->length += len;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    if (!format || !fmt) return;
    if (!fmt_check_canary(format)) { __debugbreak(); return; }
    va_list ap;
    va_start(ap, fmt);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need <= 0 || format->length + need + 1 > format->size) return;
    va_start(ap, fmt);
    vsnprintf(format->buffer, (size_t)(need + 1), fmt, ap);
    va_end(ap);
    format->buffer += need;
    format->length += need;
}

char* BeaconFormatToString(formatp* format, int* size) {
    if (!format || !size) return NULL;
    if (!fmt_check_canary(format)) { __debugbreak(); return NULL; }
    *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp* format, int value) {
    if (!format || format->length + 4 > format->size) return;
    if (!fmt_check_canary(format)) { __debugbreak(); return; }
    uint32_t out = swap_endianess((uint32_t)value);
    memcpy(format->buffer, &out, 4);
    format->buffer += 4;
    format->length += 4;
}

/* =========================================================================
 * Output API  (encrypted at rest)
 * ========================================================================= */
void BeaconPrintf(int type, char* fmt, ...) {
    (void)type;
    if (!fmt) return;

#ifdef DEBUG
    va_list dbg; va_start(dbg, fmt); vprintf(fmt, dbg); va_end(dbg);
#endif

    va_list ap;
    va_start(ap, fmt);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need <= 0) return;

    char* tmp = (char*)malloc((size_t)(need + 1));
    if (!tmp) return;

    va_start(ap, fmt);
    vsnprintf(tmp, (size_t)(need + 1), fmt, ap);
    va_end(ap);

    out_append(tmp, need);
    SecureZeroMemory(tmp, (size_t)(need + 1));
    free(tmp);
}

void BeaconOutput(int type, char* data, int len) {
    (void)type;
    if (!data || len <= 0) return;
    out_append(data, len);
}

/* Transfers ownership.  Decrypts, resets state, wipes key. */
char* BeaconGetOutputData(int* outsize) {
    if (!outsize) return NULL;

    if (!g_out_buf || g_out_offset == 0) {
        *outsize = 0;
        return NULL;
    }

    /* Decrypt in place */
    out_xor(g_out_buf, g_out_offset, g_out_key, 0);

    char* out = g_out_buf;
    *outsize  = g_out_size;

    /* Wipe internal state – key, pointers, counters */
    g_out_buf    = NULL;
    g_out_size   = 0;
    g_out_offset = 0;
    SecureZeroMemory(&g_out_key, sizeof(g_out_key));
    InterlockedExchange(&g_out_key_init, 0);   /* allow re-keying next session */

    return out;
}

/* =========================================================================
 * Token API
 * ========================================================================= */
BOOL BeaconUseToken(HANDLE token) { return SetThreadToken(NULL, token); }

void BeaconRevertToken(void) { RevertToSelf(); }

BOOL BeaconIsAdmin(void) {
    BOOL is_admin = FALSE;
    PSID admin_sid = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &admin_sid)) {
        CheckTokenMembership(NULL, admin_sid, &is_admin);
        FreeSid(admin_sid);
    }
    return is_admin;
}

/* =========================================================================
 * Spawn / inject
 * ========================================================================= */
void BeaconGetSpawnTo(BOOL x86, char* buffer, int length) {
    if (!buffer || length <= 0) return;
    const char* path = x86
        ? "C:\\Windows\\"X86PATH"\\"DEFAULTPROCESSNAME
        : "C:\\Windows\\"X64PATH"\\"DEFAULTPROCESSNAME;
    if ((int)strlen(path) >= length) return;
    memcpy(buffer, path, strlen(path) + 1);
}

BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                 STARTUPINFO* sInfo, PROCESS_INFORMATION* pInfo) {
    const char* path = x86
        ? "C:\\Windows\\"X86PATH"\\"DEFAULTPROCESSNAME
        : "C:\\Windows\\"X64PATH"\\"DEFAULTPROCESSNAME;
    return CreateProcessA(NULL, (char*)path, NULL, NULL, TRUE,
                          CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
}

void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len,
                         int p_offset, char* arg, int a_len) {
    (void)hProc; (void)pid; (void)payload; (void)p_len;
    (void)p_offset; (void)arg; (void)a_len;
}

void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload,
                                  int p_len, int p_offset, char* arg, int a_len) {
    (void)pInfo; (void)payload; (void)p_len;
    (void)p_offset; (void)arg; (void)a_len;
}

void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo) {
    if (!pInfo) return;
    CloseHandle(pInfo->hThread);
    CloseHandle(pInfo->hProcess);
}

BOOL toWideChar(char* src, wchar_t* dst, int max) {
    if (!src || !dst || max < (int)sizeof(wchar_t)) return FALSE;
    return MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS,
                               src, -1, dst, max / (int)sizeof(wchar_t));
}

#endif /* _WIN32 */