#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#if defined(_WIN32)
#include <windows.h>
#include "beacon_compatibility.h"
#endif

#include "COFFLoader.h"

/* =========================================================================
 * Debug helpers
 * ========================================================================= */
#ifdef DEBUG
#  define DBG(fmt, ...)  fprintf(stderr, "[COFF] " fmt "\n", ##__VA_ARGS__)
#else
#  define DBG(fmt, ...)  ((void)0)
#endif

/* =========================================================================
 * Architecture-specific import prefix
 * ========================================================================= */
#if defined(__x86_64__) || defined(_WIN64)
#  define IMPORT_PREFIX      "__imp_"
#  define IMPORT_PREFIX_LEN  6u
#else
#  define IMPORT_PREFIX      "__imp__"
#  define IMPORT_PREFIX_LEN  7u
#endif

/* =========================================================================
 * Page size for guard pages
 * ========================================================================= */
#define PAGE_SIZE_BYTES  4096u

/* =========================================================================
 * Global initialisation state
 * =========================================================================
 * g_loader_ready: 0 = uninitialised, 2 = ready.
 * All API functions except CoffLoaderInit check this first.
 * ========================================================================= */
#if defined(_WIN32)
static CRITICAL_SECTION  g_cs;
static HANDLE            g_private_heap = NULL;
static volatile LONG     g_loader_ready = 0;   /* 0=no, 1=initing, 2=yes */
static volatile uint32_t g_timeout_ms   = COFF_DEFAULT_TIMEOUT_MS;

/* Internal: assert the loader has been initialised */
#define REQUIRE_INIT() \
    do { if (InterlockedCompareExchange(&g_loader_ready, 2, 2) != 2) \
             return COFF_ERR_NOT_INITIALISED; } while(0)

#define REQUIRE_INIT_VOID() \
    do { if (InterlockedCompareExchange(&g_loader_ready, 2, 2) != 2) return; } while(0)

/**
 * @brief Acquire the loader-wide critical section.
 */
static void cs_lock(void)   { EnterCriticalSection(&g_cs); }

/**
 * @brief Release the loader-wide critical section.
 */
static void cs_unlock(void) { LeaveCriticalSection(&g_cs); }

/**
 * @brief Allocate zeroed memory from the loader's private heap.
 * @param sz Number of bytes requested (0 is treated as 1).
 * @return Pointer to zeroed memory, or NULL if the heap is missing or
 *         allocation fails.
 */
static void* priv_alloc(size_t sz) {
    if (!g_private_heap) return NULL;
    if (sz == 0) sz = 1;
    return HeapAlloc(g_private_heap, HEAP_ZERO_MEMORY, sz);
}

/**
 * @brief Free memory previously returned by priv_alloc.
 * @param p Pointer to free; NULL is a no-op.
 */
static void priv_free(void* p) {
    if (p && g_private_heap) HeapFree(g_private_heap, 0, p);
}

#else
/* Non-Windows stubs */
static volatile uint32_t g_timeout_ms = COFF_DEFAULT_TIMEOUT_MS;
#define REQUIRE_INIT()      ((void)0)
#define REQUIRE_INIT_VOID() ((void)0)

/** @brief No-op on non-Windows builds. */
static void cs_lock(void)   {}
/** @brief No-op on non-Windows builds. */
static void cs_unlock(void) {}

/**
 * @brief calloc-backed allocator used when the OS-specific path is unavailable.
 * @param sz Bytes to allocate.
 * @return Zeroed memory or NULL.
 */
static void* priv_alloc(size_t sz) { return calloc(1, sz ? sz : 1); }

/**
 * @brief free() wrapper paired with the non-Windows priv_alloc.
 * @param p Pointer to free.
 */
static void  priv_free(void* p)    { free(p); }
#endif

/**
 * @brief Initialise the loader: private heap, critical section and the
 *        compiler-internal exception handler used by BOF SEH tables.
 *        Idempotent and thread-safe.
 * @return COFF_SUCCESS on success or already-initialised, COFF_ERR_ALLOC_FAIL
 *         if HeapCreate fails.
 */
coff_error_t CoffLoaderInit(void) {
#if defined(_WIN32)
    // fprintf(stderr, "[D] CoffLoaderInit entry\n"); fflush(stderr);
    /* Atomically claim the init slot */
    if (InterlockedCompareExchange(&g_loader_ready, 1, 0) != 0) {
        /* Already initialised or being initialised by another thread */
        while (InterlockedCompareExchange(&g_loader_ready, 2, 2) != 2)
            Sleep(0);
        return COFF_SUCCESS;
    }

    /* Create private heap – HEAP_NO_SERIALIZE because we use our own CS */
    g_private_heap = HeapCreate(HEAP_NO_SERIALIZE, 0, 0);
    if (!g_private_heap) {
        InterlockedExchange(&g_loader_ready, 0);
        return COFF_ERR_ALLOC_FAIL;
    }
    // fprintf(stderr, "[D] HeapCreate done: %p\n", g_private_heap); fflush(stderr);

    InitializeCriticalSectionAndSpinCount(&g_cs, 4000);
    // fprintf(stderr, "[D] CS init done\n"); fflush(stderr);

    /*
     * __C_specific_handler / _except_handler4 are compiler-internal symbols.
     * They are NOT exported by ntdll or kernel32 so GetProcAddress always
     * returns NULL.  <excpt.h> (pulled in by <windows.h>) already declares
     * them with their real signatures — just take the address directly.
     * The linker resolves it from the same CRT the loader is linked against,
     * which is the same one BOFs' SEH tables reference.
     */
#if defined(__x86_64__) || defined(_WIN64)
    FARPROC csh = (FARPROC)__C_specific_handler;
#else
    FARPROC csh = (FARPROC)_except_handler4;
#endif
    // fprintf(stderr, "[D] csh=%p\n", (void*)csh); fflush(stderr);

    /* Store into the compatibility table */
    extern unsigned char* InternalFunctions[30][2];
    InternalFunctions[29][1] = (unsigned char*)(void*)csh;

    // fprintf(stderr, "[D] CSH stored, calling InitInternalFunctions\n"); fflush(stderr);
    extern void InitInternalFunctions(void);
    InitInternalFunctions();
    // fprintf(stderr, "[D] InitInternalFunctions returned\n"); fflush(stderr);

    InterlockedExchange(&g_loader_ready, 2);
    return COFF_SUCCESS;
#else
    return COFF_SUCCESS;
#endif
}

/**
 * @brief Release loader-global resources (critical section, private heap).
 *        Safe to call when uninitialised.
 */
void CoffLoaderTeardown(void) {
#if defined(_WIN32)
    if (InterlockedCompareExchange(&g_loader_ready, 0, 2) != 2)
        return;   /* not initialised, nothing to do */

    DeleteCriticalSection(&g_cs);

    if (g_private_heap) {
        HeapDestroy(g_private_heap);
        g_private_heap = NULL;
    }
#endif
}

/**
 * @brief Set the watchdog timeout used by CoffRun.
 * @param ms Maximum BOF runtime in milliseconds.
 */
void CoffSetTimeout(uint32_t ms) {
#if defined(_WIN32)
    InterlockedExchange((LONG*)&g_timeout_ms, (LONG)ms);
#else
    g_timeout_ms = ms;
#endif
}

/**
 * @brief Derive a per-run 64-bit key from stack address + high-resolution
 *        timer state. Used to obfuscate section bytes and the import GOT
 *        while the BOF is not actively executing.
 * @return Non-zero pseudo-random key.
 */
static uint64_t derive_runtime_key(void) {
    volatile uint8_t sp = 0;
    uint64_t addr = (uint64_t)(uintptr_t)&sp;
#if defined(_WIN32)
    LARGE_INTEGER li; QueryPerformanceCounter(&li);
    uint64_t t1 = (uint64_t)li.QuadPart;
    uint64_t t2 = GetTickCount64();
#else
    uint64_t t1 = addr ^ 0xDEADBEEFCAFEBABEULL;
    uint64_t t2 = (uint64_t)(uintptr_t)derive_runtime_key;
#endif
    uint64_t x = t1 ^ (t2 << 17) ^ addr;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    x *= 0x2545F4914F6CDD1DULL;
    return x ? x : 0xA5A5A5A5A5A5A5A5ULL;
}

/**
 * @brief Rotate the runtime key for at-rest storage in the ctx.
 * @param k Plaintext key.
 * @return Obfuscated key.
 */
static uint64_t obfuscate_key(uint64_t k)   { return (k >> 13) | (k << 51); }

/**
 * @brief Inverse of obfuscate_key.
 * @param o Obfuscated key.
 * @return Plaintext key.
 */
static uint64_t deobfuscate_key(uint64_t o) { return (o << 13) | (o >> 51); }

/**
 * @brief XOR a buffer in place with a xorshift64-derived keystream.
 *        Symmetric: calling twice with the same key restores the buffer.
 * @param buf Buffer to encrypt/decrypt.
 * @param len Length in bytes.
 * @param key 64-bit seed.
 */
static void xor_crypt(uint8_t* buf, size_t len, uint64_t key) {
    uint64_t ks = key;
    for (size_t i = 0; i < len; i++) {
        ks ^= ks >> 12; ks ^= ks << 25; ks ^= ks >> 27;
        buf[i] ^= (uint8_t)(ks & 0xFF);
    }
}

/**
 * @brief XOR a pointer value with a key-derived mask.  Used to keep
 *        resolved function addresses out of memory in cleartext.
 *        Symmetric.
 * @param p   Pointer (or pointer-encoded value) to transform.
 * @param key Runtime key.
 * @return Transformed pointer.
 */
static void* encrypt_ptr(void* p, uint64_t key) {
    uint64_t ks = key;
    ks ^= ks >> 12; ks ^= ks << 25; ks ^= ks >> 27;
    return (void*)((uintptr_t)p ^ (uintptr_t)(ks * 0x2545F4914F6CDD1DULL));
}
#define decrypt_ptr encrypt_ptr

/**
 * @brief Update CRC32 with a single byte.
 * @param c Current CRC accumulator.
 * @param b Next byte.
 * @return Updated CRC accumulator.
 */
static uint32_t crc32_byte(uint32_t c, uint8_t b) {
    c ^= b;
    for (int i = 0; i < 8; i++) c = (c >> 1) ^ (0xEDB88320u & -(c & 1u));
    return c;
}

/**
 * @brief CRC32 over an arbitrary buffer.
 * @param p Buffer.
 * @param n Length in bytes.
 * @return Final CRC32.
 */
static uint32_t crc32_buf(const void* p, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) c = crc32_byte(c, ((const uint8_t*)p)[i]);
    return c ^ 0xFFFFFFFFu;
}

/**
 * @brief Compute the integrity CRC32 of fields that should not change
 *        after CoffLoad completes.
 * @param ctx Loader context.
 * @return CRC32 over (section_count, import_capacity, low32(obfuscated_key)).
 */
static uint32_t ctx_crc(const coff_ctx_t* ctx) {
    uint32_t f[3] = { ctx->section_count, ctx->import_capacity,
                      (uint32_t)(ctx->obfuscated_key & 0xFFFFFFFFu) };
    return crc32_buf(f, sizeof(f));
}

/**
 * @brief Verify a ctx has not been tampered with since CoffLoad.
 * @param ctx Loader context.
 * @return COFF_SUCCESS if intact, COFF_ERR_CTX_CORRUPT otherwise,
 *         or COFF_ERR_NULL_ARG if ctx is NULL.
 */
static coff_error_t ctx_check(const coff_ctx_t* ctx) {
    if (!ctx) return COFF_ERR_NULL_ARG;
    return ctx_crc(ctx) == ctx->integrity_crc ? COFF_SUCCESS : COFF_ERR_CTX_CORRUPT;
}

/**
 * @brief Case-sensitive djb2 hash of a NUL-terminated string.
 * @param s Input string.
 * @return 32-bit hash.
 */
static uint32_t djb2(const char* s) {
    uint32_t h = 5381;
    for (; *s; s++) h = ((h << 5) + h) ^ (uint8_t)*s;
    return h;
}

/**
 * @brief Case-insensitive djb2 hash. ASCII uppercase letters are folded
 *        to lowercase before being mixed in.
 * @param s Input string.
 * @return 32-bit hash.
 */
static uint32_t djb2_lower(const char* s) {
    uint32_t h = 5381;
    for (; *s; s++) {
        uint8_t c = (uint8_t)*s;
        if (c >= 'A' && c <= 'Z') c |= 0x20;
        h = ((h << 5) + h) ^ c;
    }
    return h;
}

/**
 * @brief Default section allocator. On Windows, surrounds the writable
 *        region with PAGE_NOACCESS guard pages to catch over/underruns.
 * @param size     Section size in bytes (rounded up to a page).
 * @param user_ctx Unused.
 * @return Pointer to writable region (not the guard-page base), or NULL.
 */
static void* default_alloc(size_t size, void* user_ctx) {
    (void)user_ctx;
#if defined(_WIN32)
    /* Round section size up so the trailing guard page sits on a page
     * boundary.  VirtualProtect rounds the start address DOWN to the
     * containing page, so a misaligned trailing guard would protect the
     * section data page itself and the next memcpy faults. */
    size_t aligned = (size + PAGE_SIZE_BYTES - 1) & ~((size_t)PAGE_SIZE_BYTES - 1);
    if (aligned == 0) aligned = PAGE_SIZE_BYTES;
    size_t total = PAGE_SIZE_BYTES + aligned + PAGE_SIZE_BYTES;
    uint8_t* base = (uint8_t*)VirtualAlloc(NULL, total,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_READWRITE);
    if (!base) return NULL;
    DWORD old;
    VirtualProtect(base,                             PAGE_SIZE_BYTES, PAGE_NOACCESS, &old);
    VirtualProtect(base + PAGE_SIZE_BYTES + aligned, PAGE_SIZE_BYTES, PAGE_NOACCESS, &old);
    return base + PAGE_SIZE_BYTES;
#else
    return calloc(1, size);
#endif
}

/**
 * @brief Default section deallocator paired with default_alloc.
 * @param ptr      Pointer originally returned from default_alloc.
 * @param user_ctx Unused.
 */
static void default_free(void* ptr, void* user_ctx) {
    (void)user_ctx;
    if (!ptr) return;
#if defined(_WIN32)
    VirtualFree((uint8_t*)ptr - PAGE_SIZE_BYTES, 0, MEM_RELEASE);
#else
    free(ptr);
#endif
}

const coff_allocator_t g_coff_default_allocator = { default_alloc, default_free, NULL };

/* =========================================================================
 * Import cache
 * ========================================================================= */
typedef struct {
    uint32_t name_hash;
    void*    enc_address;
} import_cache_entry_t;

extern unsigned char* InternalFunctions[30][2];

/*
 * Self-contained NT internal type definitions.
 *
 * MinGW's <windows.h> does not expose PEB, UNICODE_STRING, or the full
 * LDR_DATA_TABLE_ENTRY.  <winternl.h> exists but its LDR_DATA_TABLE_ENTRY
 * omits BaseDllName/FullDllName on many MinGW distributions.
 *
 * We define everything we need from scratch using only primitive Windows
 * types (USHORT, PVOID, ULONG, WCHAR) that <windows.h> always provides.
 * The MY_ prefix avoids collisions with any partial definitions the SDK
 * may have already emitted.
 */
#if defined(_WIN32)

typedef struct _MY_UNICODE_STRING {
    USHORT Length;         /* byte length of the string, NOT including NUL */
    USHORT MaximumLength;  /* byte length of the buffer                    */
    WCHAR* Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    MY_UNICODE_STRING FullDllName;
    MY_UNICODE_STRING BaseDllName;
    ULONG       Flags;
    SHORT       LoadCount;
    SHORT       TlsIndex;
    LIST_ENTRY  HashLinks;
    PVOID       SectionPointer;
    ULONG       CheckSum;
    ULONG       TimeDateStamp;
    PVOID       LoadedImports;
    PVOID       EntryPointActivationContext;
    PVOID       PatchInformation;
} MY_LDR_DATA_TABLE_ENTRY;

/* PEB_LDR_DATA — only the fields we actually read */
typedef struct _MY_PEB_LDR_DATA {
    ULONG       Length;
    BOOL        Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
} MY_PEB_LDR_DATA;

/* PEB  only the Ldr pointer is needed */
typedef struct _MY_PEB {
    BYTE            Reserved1[2];
    BYTE            BeingDebugged;
    BYTE            Reserved2[1];
    PVOID           Reserved3[2];
    MY_PEB_LDR_DATA* Ldr;
    /* remaining fields omitted  we never access them  */
} MY_PEB;

#endif /* _WIN32 */

/* =========================================================================
 * Hash-based PE export resolution (no plaintext GetProcAddress)
 * ========================================================================= */
#if defined(_WIN32)
/* Forward declaration for forwarder recursion. */
static void* find_export_by_hash(HMODULE hmod, uint32_t func_hash);
static HMODULE find_module_by_hash(uint32_t dll_hash);
static void* resolve_forwarder(HMODULE origin_hmod,
                                const char* origin_name,
                                const char* fwd);

/**
 * @brief Resolve an exported function in a loaded module by djb2 hash of
 *        its name. Handles forwarder strings, including API-set names
 *        that contain dots inside the DLL part (the function name is
 *        everything after the LAST dot).
 * @param hmod      Module base address.
 * @param func_hash djb2 hash of the function name.
 * @return Function address or NULL if not found / forwarder unresolvable.
 */
static void* find_export_by_hash(HMODULE hmod, uint32_t func_hash) {
    if (!hmod) return NULL;
    uint8_t* base = (uint8_t*)hmod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    DWORD exp_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!exp_rva) return NULL;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + exp_rva);
    DWORD* names  = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords   = (WORD*) (base + exp->AddressOfNameOrdinals);
    DWORD* funcs  = (DWORD*)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (djb2((const char*)(base + names[i])) != func_hash) continue;
        DWORD fn_rva = funcs[ords[i]];

        /* Forwarder?  RVA falls inside [exp_rva, exp_rva+exp_size). */
        if (fn_rva >= exp_rva && fn_rva < exp_rva + exp_size) {
            return resolve_forwarder(hmod, (const char*)(base + names[i]), (const char*)(base + fn_rva));
        }
        return (void*)(base + fn_rva);
    }
    return NULL;
}

/**
 * @brief Resolve a forwarder string by following the chain through
 *        api-set redirection and nested forwarders.  Falls back to
 *        GetProcAddress on the originating module when manual resolution
 *        cannot make progress (api-set tables, hot-patched exports).
 *
 * @param origin_hmod  Module the forwarder was found in (used as the
 *                     final GetProcAddress fallback target).
 * @param origin_name  The function name as it appeared in origin_hmod's
 *                     export table.  Read directly from that table, so
 *                     no plaintext name needs to live in this binary.
 * @param fwd          NUL-terminated forwarder string "DllName.FuncName".
 * @return Resolved function address, or NULL.
 */
static void* resolve_forwarder(HMODULE origin_hmod,
                                const char* origin_name,
                                const char* fwd)
{
    /* Split forwarder on the LAST dot.  The DLL part may contain dots
     * (api-set names use hyphens, but legacy fwd strings sometimes carry
     * ".dll"), so last-dot is the safe split point. */
    const char* dot = NULL;
    for (const char* c = fwd; *c; c++) {
        if (*c == '.') dot = c;
    }
    if (!dot) return NULL;

    char dllname[128], funcname[128];
    size_t dl = (size_t)(dot - fwd);
    if (dl == 0 || dl >= sizeof(dllname) - 5) goto fallback;
    memcpy(dllname, fwd, dl);
    dllname[dl] = '\0';

    /* Append ".dll" if no extension is already present. */
    bool has_ext = false;
    for (size_t k = 0; k < dl; k++) {
        if (dllname[k] == '.') { has_ext = true; break; }
    }
    if (!has_ext) memcpy(dllname + dl, ".dll", 5);

    const char* fn_src = dot + 1;
    size_t fl = strlen(fn_src);
    if (fl == 0 || fl >= sizeof(funcname)) goto fallback;
    memcpy(funcname, fn_src, fl + 1);

    /* Ordinal forwarders ("DLLNAME.#123") are uncommon and not handled
     * by the manual path.  Fall straight to the API. */
    if (funcname[0] == '#') goto fallback;

    /* api-set names are redirected by a PEB-resident table our walker
     * cannot read.  Detect by prefix and skip the manual path. */
    if ((dllname[0] == 'a' || dllname[0] == 'A') &&
        (dllname[1] == 'p' || dllname[1] == 'P') &&
        (dllname[2] == 'i' || dllname[2] == 'I') &&
         dllname[3] == '-') {
        goto fallback;
    }

    /* Legacy "DLL.Function" forwarder — resolve manually. */
    uint32_t lh = djb2_lower(dllname);
    uint32_t fh = djb2(funcname);
    HMODULE m = find_module_by_hash(lh);
    if (!m) m = LoadLibraryA(dllname);
    if (!m) goto fallback;

    /* Avoid trivial recursion: if the resolved module is the originating
     * module, the manual path will loop.  Let the API resolve it. */
    if (m == origin_hmod) goto fallback;

    void* result = find_export_by_hash(m, fh);
    if (result) return result;

fallback:
    /* Hand it to GetProcAddress on the originating module with the name
     * we already have from that module's export table.  The Windows
     * loader walks api-set redirection internally and is correct across
     * versions; we are not. */
    return (void*)GetProcAddress(origin_hmod, origin_name);
}

/**
 * @brief Find a loaded module by case-insensitive djb2 hash of its base
 *        name (e.g. "kernel32.dll"). Walks the PEB loader list directly
 *        rather than calling GetModuleHandle.
 * @param dll_hash djb2_lower hash of the base DLL name (with extension).
 * @return Module base address or NULL if not loaded.
 */
static HMODULE find_module_by_hash(uint32_t dll_hash) {
    /*
     * Read the PEB address from the GS/FS segment register.
     * __readgsqword / __readfsdword are intrinsics on MSVC.
     * On MinGW we use inline asm because the intrinsics are not always
     * available, particularly for __readfsdword on x86.
     */
#if defined(__GNUC__) || defined(__clang__)
#  ifdef _WIN64
    MY_PEB* peb;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
#  else
    MY_PEB* peb;
    __asm__ volatile ("movl %%fs:0x30, %0" : "=r"(peb));
#  endif
#else  /* MSVC */
#  ifdef _WIN64
    MY_PEB* peb = (MY_PEB*)__readgsqword(0x60);
#  else
    MY_PEB* peb = (MY_PEB*)__readfsdword(0x30);
#  endif
#endif

    if (!peb || !peb->Ldr) return NULL;

    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* cur  = head->Flink;
    while (cur && cur != head) {
        MY_LDR_DATA_TABLE_ENTRY* e = CONTAINING_RECORD(
            cur, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (e->BaseDllName.Buffer) {
            char narrow[64] = {0};
            int  n = e->BaseDllName.Length / 2;  /* Length is in bytes */
            if (n >= (int)sizeof(narrow)) n = (int)sizeof(narrow) - 1;
            for (int i = 0; i < n; i++)
                narrow[i] = (char)e->BaseDllName.Buffer[i];
            if (djb2_lower(narrow) == dll_hash)
                return (HMODULE)e->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}
#endif /* _WIN32 */

/**
 * @brief Public hardened export resolver. Walks the PEB by hash first,
 *        then falls back to LoadLibraryA / GetProcAddress so callers do
 *        not have to know which DLLs are already in the process.
 * @param lib_name  DLL base name (e.g. "kernel32.dll"). Case-insensitive.
 * @param func_name Exported function name. Case-sensitive.
 * @return Function address or NULL if not found.
 */
void* CoffResolveExport(const char* lib_name, const char* func_name) {
    if (!lib_name || !func_name) return NULL;
#if defined(_WIN32)
    uint32_t lib_hash  = djb2_lower(lib_name);
    uint32_t func_hash = djb2(func_name);

    HMODULE hmod = find_module_by_hash(lib_hash);
    if (!hmod) {
        hmod = LoadLibraryA(lib_name);
        if (!hmod) return NULL;
    }
    void* fp = find_export_by_hash(hmod, func_hash);
    if (!fp) fp = (void*)GetProcAddress(hmod, func_name);
    return fp;
#else
    return NULL;
#endif
}

// Non hash walker version for testing
// void* CoffResolveExport(const char* lib_name, const char* func_name) {
//     if (!lib_name || !func_name) return NULL;
//     HMODULE hmod = GetModuleHandleA(lib_name);
//     if (!hmod) hmod = LoadLibraryA(lib_name);
//     if (!hmod) return NULL;
//     return (void*)GetProcAddress(hmod, func_name);
// }

/**
 * @brief Return true if string s begins with prefix p.
 * @param s String to test.
 * @param p Prefix to look for.
 * @return true if s starts with p.
 */
static bool str_pfx(const char* s, const char* p) {
    return strncmp(s, p, strlen(p)) == 0;
}

/* =========================================================================
 * REL32 trampoline allocator
 * =========================================================================
 * For bare-name external REL32 relocations we cannot point the displacement
 * at the GOT slot (the BOF would execute the GOT bytes as instructions).
 * Instead we write a 14-byte trampoline somewhere within ±2GB of the patch
 * site and point the REL32 at that.
 *
 * The trampoline area lives in the slack space at the end of each section's
 * page-aligned allocation: section data is sh->SizeOfRawData bytes, exec_size
 * is rounded up to a page (often 4096), giving (exec_size - SizeOfRawData)
 * bytes of free space.  Since the trampolines sit in the section memory,
 * the existing XOR-encryption + VirtualProtect lifecycle covers them for free.
 *
 * Per section we track next_tramp_offset, which starts at SizeOfRawData and
 * grows toward exec_size.  Each trampoline takes 16 bytes.
 * ========================================================================= */
#define TRAMP_BYTES 16

typedef struct {
    uint32_t section_idx;
    uint32_t next_offset;     /* next free byte in slack region */
    uint32_t raw_data_size;   /* SizeOfRawData — where slack begins */
} tramp_alloc_t;

/**
 * @brief Emit a 16-byte trampoline inside section `si`'s slack region.
 *        Layout: ff 25 00 00 00 00 <8-byte target> <2 pad bytes>
 *        i.e. an absolute indirect jump that loads the target from the
 *        immediately following bytes. Used to convert a 32-bit REL32 call
 *        site into a jump to a far function (>2 GB away).
 * @param ctx         Loader context.
 * @param si          Section index that owns the patch site.
 * @param next_off    Per-section running offset (updated in place).
 * @param target_addr Absolute address the trampoline jumps to.
 * @return Address of the trampoline (where the REL32 should point), or
 *         NULL if the slack region is exhausted.
 */
static uint8_t* alloc_trampoline(coff_ctx_t* ctx, uint16_t si,
                                  uint32_t* next_off,
                                  void* target_addr) {
    if (!ctx || si >= ctx->section_count) return NULL;
    uint32_t exec_size = ctx->sections[si].exec_size;
    if (*next_off + TRAMP_BYTES > exec_size) return NULL;

    uint8_t* base = (uint8_t*)ctx->sections[si].exec_ptr;
    uint8_t* t    = base + *next_off;

    t[0] = 0xff; t[1] = 0x25;                       /* jmp [rip+0] */
    t[2] = 0x00; t[3] = 0x00; t[4] = 0x00; t[5] = 0x00;
    memcpy(t + 6, &target_addr, sizeof(void*));     /* 8-byte target */
    /* t[14..15] = pad */

    *next_off += TRAMP_BYTES;
    return t;
}

/**
 * @brief Exact-match lookup in the InternalFunctions[] compatibility table.
 *        Handles the special-cased __C_specific_handler slot at index 29.
 * @param name Symbol name to look up.
 * @return Function pointer or NULL if not present.
 */
static void* internal_lookup_exact(const char* name) {
    if (!name) return NULL;
    if (strcmp(name, "__C_specific_handler") == 0)
        return InternalFunctions[29][1];
    for (int i = 0; i < 30; i++) {
        if (InternalFunctions[i][0] &&
            strcmp(name, (char*)InternalFunctions[i][0]) == 0)
            return InternalFunctions[i][1];
    }
    return NULL;
}

/* Fallback DLL list searched in order for unprefixed externals.
 * msvcrt first because most bare names are CRT (calloc/free/memcpy/etc). */
static const char* g_fallback_dlls[] = {
    "msvcrt.dll", "kernel32.dll", "user32.dll", "advapi32.dll",
    "ws2_32.dll", "iphlpapi.dll", "secur32.dll", "ntdll.dll",
    NULL
};

/* MinGW-static-linked symbols that no DLL exports.
 * These are pulled in by libmingwex.a when the loader links, so we can take
 * their address directly and hand them to a BOF that references them.
 * Declared with the C signatures MinGW uses. */
extern int __mingw_vsnprintf(char*, size_t, const char*, va_list);
extern int __ms_vsnprintf  (char*, size_t, const char*, va_list);
extern int __mingw_vsprintf(char*, const char*, va_list);
extern int __mingw_vprintf (const char*, va_list);

typedef struct { const char* name; void* fn; } static_sym_t;
static const static_sym_t g_static_syms[] = {
    { "__mingw_vsnprintf", (void*)&__mingw_vsnprintf },
    { "__ms_vsnprintf",    (void*)&__ms_vsnprintf    },
    { "__mingw_vsprintf",  (void*)&__mingw_vsprintf  },
    { "__mingw_vprintf",   (void*)&__mingw_vprintf   },
    { NULL, NULL }
};

/**
 * @brief Look up a statically-linked helper (mingwex etc) by name.
 * @param name Symbol name.
 * @return Function pointer or NULL.
 */
static void* static_lookup(const char* name) {
    for (int i = 0; g_static_syms[i].name; i++)
        if (strcmp(name, g_static_syms[i].name) == 0)
            return g_static_syms[i].fn;
    return NULL;
}

/**
 * @brief Resolve an external symbol that has no library qualifier.
 *        Order: internal Beacon table → static MinGW helpers → fallback DLLs.
 * @param name Bare symbol name.
 * @return Function pointer or NULL.
 */
static void* resolve_bare_name(const char* name) {
    /* Internal table first (BeaconPrintf, BeaconOutput, etc) */
    void* p = internal_lookup_exact(name);
    if (p) return p;
    /* Then statically-linked symbols (mingwex helpers etc) */
    p = static_lookup(name);
    if (p) return p;
    /* Then walk the fallback DLLs */
    for (int i = 0; g_fallback_dlls[i]; i++) {
        p = CoffResolveExport(g_fallback_dlls[i], name);
        if (p) return p;
    }
    return NULL;
}

/**
 * @brief Resolve any symbol name appearing in a COFF relocation.
 *        Handles three forms:
 *          1. "__C_specific_handler" (compiler-internal SEH handler)
 *          2. "__imp_LIB$func"        (Cobalt Strike dynamic import)
 *             also "__imp_<bare>"     (MinGW-emitted plain import)
 *          3. bare name               (direct REL32 call)
 * @param sym Symbol name from the COFF symbol table.
 * @return Function pointer or NULL.
 */
static void* resolve_symbol(const char* sym) {
    if (!sym) return NULL;

    /* 1. __C_specific_handler — special case, bare name */
    if (strcmp(sym, "__C_specific_handler") == 0)
        return InternalFunctions[29][1];

    /* 2. __imp_<...> form */
    if (str_pfx(sym, IMPORT_PREFIX)) {
        const char* bare = sym + IMPORT_PREFIX_LEN;

        char buf[256];
        strncpy(buf, bare, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        char* dollar = strchr(buf, '$');
        if (dollar) {
            /* __imp_LIBNAME$func — standard Cobalt Strike form */
            *dollar = '\0';
            char* func = dollar + 1;
            char* at   = strchr(func, '@');
            if (at) *at = '\0';
            DBG("resolve lib='%s' func='%s'", buf, func);
            return CoffResolveExport(buf, func);
        }

        /* __imp_<bareName> — no $ separator.  Could be:
         *   - a kernel32/msvcrt/etc import emitted by MinGW
         *   - an internal Beacon* function (rare with __imp_)
         */
        DBG("resolve bare-imp '%s'", bare);
        return resolve_bare_name(bare);
    }

    /* 3. Bare name (no __imp_ prefix) — direct REL32 call.
     *    BeaconPrintf, calloc, free, __mingw_vsnprintf, etc. */
    DBG("resolve bare '%s'", sym);
    return resolve_bare_name(sym);
}

/**
 * @brief Look up an already-resolved import in the per-ctx cache and
 *        decrypt its slot so the caller sees the cleartext address.
 * @param ctx  Loader context.
 * @param name Symbol name (matched by hash).
 * @param key  Runtime key for decrypting the cached address.
 * @return Pointer to the cleartext slot in ctx->import_table, or NULL
 *         if the symbol is not yet cached.
 */
static void** find_cached_import(coff_ctx_t* ctx, const char* name,
                                  uint64_t key) {
    if (!ctx || !ctx->import_table || !ctx->import_count) return NULL;
    import_cache_entry_t* cache =
        (import_cache_entry_t*)ctx->import_table[ctx->import_capacity - 1];
    if (!cache) return NULL;
    uint32_t h = djb2(name);
    for (uint32_t i = 0; i < ctx->import_count; i++) {
        if (cache[i].name_hash == h) {
            ctx->import_table[i] = decrypt_ptr(cache[i].enc_address, key);
            return &ctx->import_table[i];
        }
    }
    return NULL;
}

/**
 * @brief Insert a newly-resolved import into the ctx cache. Stores the
 *        cleartext address in the GOT slot and the encrypted address in
 *        the parallel hash-keyed cache for later lookup.
 * @param ctx  Loader context.
 * @param name Symbol name.
 * @param addr Resolved function address.
 * @param key  Runtime key.
 * @return Pointer to the GOT slot (used as the relocation target for
 *         __imp_ indirect calls), or NULL if the cache is full.
 */
static void** add_cached_import(coff_ctx_t* ctx, const char* name,
                                 void* addr, uint64_t key) {
    if (!ctx || ctx->import_count >= ctx->import_capacity - 1) return NULL;
    import_cache_entry_t* cache =
        (import_cache_entry_t*)ctx->import_table[ctx->import_capacity - 1];
    if (!cache) return NULL;
    uint32_t slot = ctx->import_count++;
    ctx->import_table[slot] = addr;
    cache[slot].name_hash   = djb2(name);
    cache[slot].enc_address = encrypt_ptr(addr, key);
    return &ctx->import_table[slot];
}

/**
 * @brief Re-encrypt every GOT slot in place. Called between BOF runs so
 *        cleartext function pointers do not sit in memory while idle.
 * @param ctx Loader context.
 * @param key Runtime key.
 */
static void reimport_encrypt_all(coff_ctx_t* ctx, uint64_t key) {
    import_cache_entry_t* cache =
        (import_cache_entry_t*)ctx->import_table[ctx->import_capacity - 1];
    if (!cache) return;
    for (uint32_t i = 0; i < ctx->import_count; i++)
        ctx->import_table[i] = encrypt_ptr(ctx->import_table[i], key);
}

/* =========================================================================
 * Bounds-check macro
 * ========================================================================= */
#define BOUNDS_CHECK(off, sz, fsz, err) \
    do { if ((uint64_t)(off)+(uint64_t)(sz) > (uint64_t)(fsz)) return (err); } while(0)

/**
 * @brief Parse a COFF object, allocate executable memory for each section,
 *        resolve every external symbol and apply all relocations. Sections
 *        and the import GOT are left XOR-encrypted at return.
 * @param coff_data Raw COFF bytes.
 * @param filesize  Size of coff_data in bytes.
 * @param allocator Section allocator override; pass NULL for the default
 *                  guard-page allocator.
 * @param ctx_out   Receives a heap-allocated coff_ctx_t* on success.
 * @return COFF_SUCCESS or a specific COFF_ERR_* on failure. On failure
 *         *ctx_out is left untouched.
 */
coff_error_t CoffLoad(
    const uint8_t*          coff_data,
    uint32_t                filesize,
    const coff_allocator_t* allocator,
    coff_ctx_t**            ctx_out)
{
    REQUIRE_INIT();
    if (!coff_data || !ctx_out)                return COFF_ERR_NULL_ARG;
    if (filesize < sizeof(coff_file_header_t)) return COFF_ERR_FILE_TOO_SMALL;

    const coff_allocator_t* alloc = allocator ? allocator : &g_coff_default_allocator;
    const coff_file_header_t* hdr = (const coff_file_header_t*)coff_data;

#if defined(__x86_64__) || defined(_WIN64)
    if (hdr->Machine != MACHINETYPE_AMD64) return COFF_ERR_BAD_MACHINE;
#else
    if (hdr->Machine != MACHINETYPE_I386)  return COFF_ERR_BAD_MACHINE;
#endif
    if (hdr->NumberOfSections > COFF_MAX_SECTIONS) return COFF_ERR_SECTION_OVERFLOW;
    if (hdr->PointerToSymbolTable < sizeof(coff_file_header_t))
        return COFF_ERR_BAD_SYMTAB_OFFSET;

    uint64_t symtab_end = (uint64_t)hdr->PointerToSymbolTable +
                          (uint64_t)hdr->NumberOfSymbols * sizeof(coff_sym_t);
    if (symtab_end > filesize) return COFF_ERR_SYMTAB_OVERFLOW;

    BOUNDS_CHECK(symtab_end, sizeof(uint32_t), filesize, COFF_ERR_STRTAB_OVERFLOW);
    uint32_t strtab_size;
    memcpy(&strtab_size, coff_data + symtab_end, sizeof(uint32_t));
    BOUNDS_CHECK(symtab_end, strtab_size, filesize, COFF_ERR_STRTAB_OVERFLOW);

    uint64_t sect_end = sizeof(coff_file_header_t) + hdr->SizeOfOptionalHeader +
                        (uint64_t)hdr->NumberOfSections * sizeof(coff_sect_t);
    if (sect_end > filesize) return COFF_ERR_SECTION_OVERFLOW;

    uint32_t total_relocs = 0;
    for (uint16_t s = 0; s < hdr->NumberOfSections; s++) {
        const coff_sect_t* sh = (const coff_sect_t*)(
            coff_data + sizeof(coff_file_header_t) + hdr->SizeOfOptionalHeader +
            (uint64_t)s * sizeof(coff_sect_t));
        if (sh->PointerToRelocations && sh->NumberOfRelocations)
            BOUNDS_CHECK(sh->PointerToRelocations,
                         (uint64_t)sh->NumberOfRelocations * sizeof(coff_reloc_t),
                         filesize, COFF_ERR_RELOC_OVERFLOW);
        if (sh->PointerToRawData && sh->SizeOfRawData)
            BOUNDS_CHECK(sh->PointerToRawData, sh->SizeOfRawData,
                         filesize, COFF_ERR_RAWDATA_OVERFLOW);
        total_relocs += sh->NumberOfRelocations;
    }

    uint64_t runtime_key = derive_runtime_key();

    coff_ctx_t* ctx = (coff_ctx_t*)priv_alloc(sizeof(coff_ctx_t));
    if (!ctx) return COFF_ERR_ALLOC_FAIL;
    ctx->allocator      = *alloc;
    ctx->obfuscated_key = obfuscate_key(runtime_key);
    ctx->private_heap   = (void*)g_private_heap;

    uint32_t import_cap = total_relocs + 2;
    ctx->import_table = (void**)priv_alloc(import_cap * sizeof(void*));
    if (!ctx->import_table) { priv_free(ctx); return COFF_ERR_ALLOC_FAIL; }
    ctx->import_capacity = import_cap;

    import_cache_entry_t* name_cache =
        (import_cache_entry_t*)priv_alloc(import_cap * sizeof(import_cache_entry_t));
    if (!name_cache) {
        priv_free(ctx->import_table); priv_free(ctx);
        return COFF_ERR_ALLOC_FAIL;
    }
    ctx->import_table[import_cap - 1] = name_cache;

    const coff_sym_t* sym_table =
        (const coff_sym_t*)(coff_data + hdr->PointerToSymbolTable);

    /* Allocate and copy sections */
    for (uint16_t s = 0; s < hdr->NumberOfSections; s++) {
        const coff_sect_t* sh = (const coff_sect_t*)(
            coff_data + sizeof(coff_file_header_t) + hdr->SizeOfOptionalHeader +
            (uint64_t)s * sizeof(coff_sect_t));

        uint32_t alloc_sz = sh->SizeOfRawData ? sh->SizeOfRawData : 16;
        void* mem = alloc->alloc(alloc_sz, alloc->user_ctx);
        if (!mem) { ctx->section_count = s; CoffFree(&ctx); return COFF_ERR_ALLOC_FAIL; }

        if (sh->PointerToRawData && sh->SizeOfRawData)
            memcpy(mem, coff_data + sh->PointerToRawData, sh->SizeOfRawData);
        else
            memset(mem, 0, alloc_sz);

        xor_crypt((uint8_t*)mem, alloc_sz, runtime_key);

        ctx->sections[s].exec_ptr        = mem;
        ctx->sections[s].characteristics = sh->Characteristics;
#if defined(_WIN32)
        if (alloc->alloc == default_alloc) {
            size_t aligned = (alloc_sz + PAGE_SIZE_BYTES - 1) & ~((size_t)PAGE_SIZE_BYTES - 1);
            if (aligned == 0) aligned = PAGE_SIZE_BYTES;
            /* exec_size covers the whole aligned region so trampolines in the
             * slack area (SizeOfRawData .. aligned) are XOR'd and protected
             * along with the real section data. */
            ctx->sections[s].exec_size  = (uint32_t)aligned;
            ctx->sections[s].base_alloc = (uint8_t*)mem - PAGE_SIZE_BYTES;
            ctx->sections[s].base_size  = PAGE_SIZE_BYTES + aligned + PAGE_SIZE_BYTES;
        } else {
            ctx->sections[s].exec_size = alloc_sz;
            ctx->sections[s].base_alloc = mem;
            ctx->sections[s].base_size  = alloc_sz;
        }
#else
        ctx->sections[s].exec_size  = alloc_sz;
        ctx->sections[s].base_alloc = mem;
        ctx->sections[s].base_size  = alloc_sz;
#endif
    }
    ctx->section_count = hdr->NumberOfSections;

    /* Initialise per-section trampoline next-offsets. Each section's
     * trampoline region starts at SizeOfRawData (rounded up to 8) and
     * grows up to exec_size (page-aligned). */
    for (uint16_t s = 0; s < hdr->NumberOfSections; s++) {
        const coff_sect_t* sh = (const coff_sect_t*)(
            coff_data + sizeof(coff_file_header_t) + hdr->SizeOfOptionalHeader +
            (uint64_t)s * sizeof(coff_sect_t));
        ctx->tramp_next[s] = (sh->SizeOfRawData + 7u) & ~7u;
    }

    /* Apply relocations */
    for (uint16_t s = 0; s < hdr->NumberOfSections; s++) {
        const coff_sect_t* sh = (const coff_sect_t*)(
            coff_data + sizeof(coff_file_header_t) + hdr->SizeOfOptionalHeader +
            (uint64_t)s * sizeof(coff_sect_t));
        if (!sh->NumberOfRelocations || !sh->PointerToRelocations) continue;

        xor_crypt((uint8_t*)ctx->sections[s].exec_ptr,
                  ctx->sections[s].exec_size, runtime_key);

        const coff_reloc_t* relocs =
            (const coff_reloc_t*)(coff_data + sh->PointerToRelocations);

        for (uint16_t r = 0; r < sh->NumberOfRelocations; r++) {
            const coff_reloc_t* rel = &relocs[r];

#define RELOC_FAIL(e) do { \
    xor_crypt((uint8_t*)ctx->sections[s].exec_ptr, \
              ctx->sections[s].exec_size, runtime_key); \
    CoffFree(&ctx); return (e); } while(0)

            if ((uint64_t)rel->VirtualAddress + 4 > ctx->sections[s].exec_size)
                RELOC_FAIL(COFF_ERR_RELOC_OVERFLOW);
            if (rel->SymbolTableIndex >= hdr->NumberOfSymbols)
                RELOC_FAIL(COFF_ERR_SYMIDX_OOB);

            const coff_sym_t* sym = &sym_table[rel->SymbolTableIndex];
            char sym_short[9] = {0};
            const char* sym_name;
            if (sym->first.value[0] == 0) {
                uint32_t off = sym->first.value[1];
                BOUNDS_CHECK((uint64_t)hdr->PointerToSymbolTable +
                             (uint64_t)hdr->NumberOfSymbols * sizeof(coff_sym_t) + off,
                             1, filesize, COFF_ERR_STRTAB_OVERFLOW);
                sym_name = (const char*)(coff_data + hdr->PointerToSymbolTable +
                           hdr->NumberOfSymbols * sizeof(coff_sym_t) + off);
            } else {
                if (sym->first.Name[7] != '\0') {
                    memcpy(sym_short, sym->first.Name, 8); sym_name = sym_short;
                } else { sym_name = sym->first.Name; }
            }

            bool sym_defined  = sym->SectionNumber > 0;
            bool sym_external = sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL ||
                                sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL_DEF;
            void* target = NULL;

            if (sym_defined) {
                uint16_t si = (uint16_t)(sym->SectionNumber - 1);
                if (si >= ctx->section_count) RELOC_FAIL(COFF_ERR_SYMIDX_OOB);
                if (si != s)
                    xor_crypt((uint8_t*)ctx->sections[si].exec_ptr,
                              ctx->sections[si].exec_size, runtime_key);
                target = (uint8_t*)ctx->sections[si].exec_ptr + sym->Value;
                if (si != s)
                    xor_crypt((uint8_t*)ctx->sections[si].exec_ptr,
                              ctx->sections[si].exec_size, runtime_key);
            } else if (sym_external && sym->Value == 0) {
                /* Resolve the function. */
                void* resolved = NULL;
                {
                    void** cached = find_cached_import(ctx, sym_name, runtime_key);
                    if (cached) {
                        resolved = *cached;
                    } else {
                        resolved = resolve_symbol(sym_name);
                        if (!resolved) { DBG("Unresolved: %s", sym_name); RELOC_FAIL(COFF_ERR_SYMBOL_UNRESOLVED); }
                        void** slot = add_cached_import(ctx, sym_name, resolved, runtime_key);
                        if (!slot) RELOC_FAIL(COFF_ERR_ALLOC_FAIL);
                        cached = slot;
                    }

                    /* Direct call (bare name) vs indirect through GOT (__imp_).
                     * MinGW emits REL32 to bare names with `call rel32` (direct)
                     * and REL32 to __imp_<name> with `call *[rip+disp]` (indirect).
                     * For direct calls we need a trampoline because the function
                     * is typically > 2GB away (e.g. msvcrt). */
                    bool is_imp = str_pfx(sym_name, IMPORT_PREFIX);
                    if (is_imp) {
                        target = cached;        /* GOT slot for indirect call */
                    } else {
                        /* Trampoline in this section's slack region. */
                        uint8_t* tr = alloc_trampoline(ctx, s,
                            &ctx->tramp_next[s], resolved);
                        if (!tr) RELOC_FAIL(COFF_ERR_ALLOC_FAIL);
                        // fprintf(stderr, "[TR] sym='%s' resolved=%p tramp=%p target_in_tramp=%p\n",
                        //     sym_name, resolved, (void*)tr, *(void**)(tr+6));
                        // fflush(stderr);
                        target = tr;
                    }
                }
            } else { RELOC_FAIL(COFF_ERR_SYMBOL_UNRESOLVED); }

            // fprintf(stderr, "[R%u/%u] sect=%u +0x%X type=%u sym='%s' symsect=%d defined=%d external=%d target=%p\n",
            //         r, sh->NumberOfRelocations, s, rel->VirtualAddress, rel->Type,
            //         sym_name, sym->SectionNumber, sym_defined, sym_external, target);
            // fflush(stderr);

            uint8_t* patch = (uint8_t*)ctx->sections[s].exec_ptr + rel->VirtualAddress;
            uint32_t u32 = 0; uint64_t u64 = 0;

#if defined(__x86_64__) || defined(_WIN64)
            switch (rel->Type) {
            case IMAGE_REL_AMD64_ABSOLUTE: break;
            case IMAGE_REL_AMD64_ADDR64:
                memcpy(&u64, patch, 8); u64 += (uint64_t)(uintptr_t)target;
                memcpy(patch, &u64, 8); break;
            case IMAGE_REL_AMD64_ADDR32NB: {
                memcpy(&u32, patch, 4);
                intptr_t d = (intptr_t)target+(intptr_t)u32-(intptr_t)(patch+4);
                if (d>INT32_MAX||d<INT32_MIN) RELOC_FAIL(COFF_ERR_RELOC_RANGE);
                u32=(uint32_t)(int32_t)d; memcpy(patch,&u32,4); break; }
            case IMAGE_REL_AMD64_REL32: case IMAGE_REL_AMD64_REL32_1:
            case IMAGE_REL_AMD64_REL32_2: case IMAGE_REL_AMD64_REL32_3:
            case IMAGE_REL_AMD64_REL32_4: case IMAGE_REL_AMD64_REL32_5: {
                uint32_t extra = rel->Type - IMAGE_REL_AMD64_REL32;
                memcpy(&u32, patch, 4);
                intptr_t d = (intptr_t)target+(intptr_t)(int32_t)u32-
                             ((intptr_t)patch+4+(intptr_t)extra);
                if (d>INT32_MAX||d<INT32_MIN) RELOC_FAIL(COFF_ERR_RELOC_RANGE);
                u32=(uint32_t)(int32_t)d; memcpy(patch,&u32,4); break; }
            case IMAGE_REL_AMD64_SECREL:
                u32 = sym_defined ? sym->Value : 0; memcpy(patch,&u32,4); break;
            case IMAGE_REL_AMD64_SECTION: {
                uint16_t s16 = sym_defined ? sym->SectionNumber : 0;
                memcpy(patch,&s16,2); break; }
            default: RELOC_FAIL(COFF_ERR_RELOC_UNKNOWN_TYPE);
            }
#else
            switch (rel->Type) {
            case IMAGE_REL_I386_ABSOLUTE: break;
            case IMAGE_REL_I386_DIR32:
                memcpy(&u32,patch,4); u32+=(uint32_t)(uintptr_t)target;
                memcpy(patch,&u32,4); break;
            case IMAGE_REL_I386_REL32: {
                memcpy(&u32,patch,4);
                intptr_t d=(intptr_t)target+(intptr_t)(int32_t)u32-((intptr_t)patch+4);
                if(d>INT32_MAX||d<INT32_MIN) RELOC_FAIL(COFF_ERR_RELOC_RANGE);
                u32=(uint32_t)(int32_t)d; memcpy(patch,&u32,4); break; }
            case IMAGE_REL_I386_SECREL:
                u32=sym_defined?sym->Value:0; memcpy(patch,&u32,4); break;
            default: RELOC_FAIL(COFF_ERR_RELOC_UNKNOWN_TYPE);
            }
#endif
#undef RELOC_FAIL
        }
        xor_crypt((uint8_t*)ctx->sections[s].exec_ptr,
                  ctx->sections[s].exec_size, runtime_key);
    }

    reimport_encrypt_all(ctx, runtime_key);
    ctx->integrity_crc = ctx_crc(ctx);
    *ctx_out = ctx;
    return COFF_SUCCESS;
}

/**
 * @brief Apply each section's final VirtualProtect flags based on its COFF
 *        characteristics (exec/read/write/discardable). Marks the ctx as
 *        having protections applied.
 * @param ctx Loader context.
 * @return COFF_SUCCESS, COFF_ERR_NULL_ARG, COFF_ERR_NOT_INITIALISED, or
 *         COFF_ERR_CTX_CORRUPT.
 */
coff_error_t CoffApplyProtections(coff_ctx_t* ctx) {
    REQUIRE_INIT();
    if (!ctx) return COFF_ERR_NULL_ARG;
    coff_error_t ic = ctx_check(ctx);
    if (ic != COFF_SUCCESS) return ic;
#if defined(_WIN32)
    for (uint16_t s = 0; s < ctx->section_count; s++) {
        void* mem = ctx->sections[s].exec_ptr;
        if (!mem) continue;
        uint32_t ch   = ctx->sections[s].characteristics;
        bool exec     = (ch & IMAGE_SCN_MEM_EXECUTE)     != 0;
        bool write    = (ch & IMAGE_SCN_MEM_WRITE)       != 0;
        bool read     = (ch & IMAGE_SCN_MEM_READ)        != 0;
        bool discard  = (ch & IMAGE_SCN_MEM_DISCARDABLE) != 0;
        DWORD prot    = PAGE_NOACCESS;
        if      (discard)       prot = PAGE_NOACCESS;
        else if (exec && write) prot = PAGE_EXECUTE_READWRITE;
        else if (exec && read)  prot = PAGE_EXECUTE_READ;
        else if (exec)          prot = PAGE_EXECUTE;
        else if (write)         prot = PAGE_READWRITE;
        else if (read)          prot = PAGE_READONLY;
        DWORD old;
        VirtualProtect(mem, ctx->sections[s].exec_size, prot, &old);
    }
    ctx->protections_applied = true;
#else
    ctx->protections_applied = true;
#endif
    return COFF_SUCCESS;
}

#if defined(_WIN32)
/**
 * @brief Compute the VirtualProtect flag corresponding to a set of COFF
 *        section characteristics. Used by CoffRun to restore the proper
 *        protection after temporarily opening sections for decryption.
 * @param ch IMAGE_SCN_* flag bits.
 * @return PAGE_* constant.
 */
static DWORD section_prot_from_chars(uint32_t ch) {
    bool exec    = (ch & IMAGE_SCN_MEM_EXECUTE)     != 0;
    bool write   = (ch & IMAGE_SCN_MEM_WRITE)       != 0;
    bool read    = (ch & IMAGE_SCN_MEM_READ)        != 0;
    bool discard = (ch & IMAGE_SCN_MEM_DISCARDABLE) != 0;
    if (discard)       return PAGE_NOACCESS;
    if (exec && write) return PAGE_EXECUTE_READWRITE;
    if (exec && read)  return PAGE_EXECUTE_READ;
    if (exec)          return PAGE_EXECUTE;
    if (write)         return PAGE_READWRITE;
    if (read)          return PAGE_READONLY;
    return PAGE_NOACCESS;
}
#endif

/* =========================================================================
 * Watchdog thread context
 * ========================================================================= */
#if defined(_WIN32)
typedef struct {
    void   (*entry)(char*, unsigned long);
    char*    argdata;
    unsigned long argsize;
} watchdog_args_t;

/**
 * @brief Worker that actually invokes the BOF entry point. Runs on a
 *        dedicated thread so CoffRun can enforce a wall-clock timeout.
 * @param param Heap-allocated watchdog_args_t* (caller frees).
 * @return Always 0.
 */
static DWORD WINAPI bof_thread_proc(LPVOID param) {
    watchdog_args_t* a = (watchdog_args_t*)param;
    a->entry(a->argdata, a->argsize);
    return 0;
}
#endif

/**
 * @brief Locate the named entry point in the loaded ctx, decrypt section
 *        bodies + GOT, invoke the BOF on a watchdog thread, then
 *        re-encrypt everything and restore section protections.
 *
 * Protection lifecycle (Windows, default_alloc path)
 *   1. strip all sections to PAGE_READWRITE
 *   2. xor_crypt decrypt every section
 *   3. decrypt the import GOT
 *   4. raise executable sections back to their natural protection
 *   5. call the entry on a watchdog thread (or directly on fallback)
 *   6. strip all sections to PAGE_READWRITE again (even on timeout)
 *   7. xor_crypt re-encrypt every section
 *   8. re-encrypt the GOT
 *   9. restore each section's final protection
 *
 * @param ctx           Loader context (must be intact).
 * @param functionname  Entry symbol, typically "go".
 * @param coff_data     The original COFF buffer (re-read for symbol names).
 * @param filesize      Size of coff_data.
 * @param argdata       Optional argument blob passed to the BOF.
 * @param argsize       Length of argdata in bytes.
 * @return COFF_SUCCESS, COFF_ERR_ENTRY_NOT_FOUND, COFF_ERR_TIMEOUT, or
 *         another COFF_ERR_* on early failures.
 */
coff_error_t CoffRun(
    coff_ctx_t*    ctx,
    const char*    functionname,
    const uint8_t* coff_data,
    uint32_t       filesize,
    uint8_t*       argdata,
    int            argsize)
{
    REQUIRE_INIT();
    if (!ctx || !functionname || !coff_data) return COFF_ERR_NULL_ARG;
    if (filesize < sizeof(coff_file_header_t)) return COFF_ERR_FILE_TOO_SMALL;

    coff_error_t ic = ctx_check(ctx);
    if (ic != COFF_SUCCESS) return ic;

    uint64_t runtime_key = deobfuscate_key(ctx->obfuscated_key);

    const coff_file_header_t* hdr = (const coff_file_header_t*)coff_data;
    const coff_sym_t* sym_table   =
        (const coff_sym_t*)(coff_data + hdr->PointerToSymbolTable);

    char entry_buf[256];
    const char* entry_name = functionname;
#if !(defined(__x86_64__) || defined(_WIN64))
    if (snprintf(entry_buf, sizeof(entry_buf), "_%s", functionname)
            >= (int)sizeof(entry_buf))
        return COFF_ERR_ENTRY_NOT_FOUND;
    entry_name = entry_buf;
#else
    (void)entry_buf;
#endif

    uint32_t sym_idx = 0;
    while (sym_idx < hdr->NumberOfSymbols) {
        const coff_sym_t* sym = &sym_table[sym_idx];

        char sym_short[9] = {0};
        const char* sym_name;
        if (sym->first.value[0] == 0) {
            sym_name = (const char*)(coff_data + hdr->PointerToSymbolTable +
                       hdr->NumberOfSymbols * sizeof(coff_sym_t) +
                       sym->first.value[1]);
        } else {
            if (sym->first.Name[7] != '\0') {
                memcpy(sym_short, sym->first.Name, 8); sym_name = sym_short;
            } else { sym_name = sym->first.Name; }
        }

        if (strcmp(sym_name, entry_name) == 0 && sym->SectionNumber > 0) {
            uint16_t si = (uint16_t)(sym->SectionNumber - 1);
            if (si >= ctx->section_count) return COFF_ERR_ENTRY_NOT_FOUND;

            /* ----------------------------------------------------------
             * Step 1: Open all sections for writing so we can decrypt.
             * ---------------------------------------------------------- */
#if defined(_WIN32)
            for (uint16_t i = 0; i < ctx->section_count; i++) {
                if (!ctx->sections[i].exec_ptr) continue;
                DWORD old;
                VirtualProtect(ctx->sections[i].exec_ptr,
                               ctx->sections[i].exec_size,
                               PAGE_READWRITE, &old);
            }
#endif

            /* ----------------------------------------------------------
             * Step 2 & 3: Decrypt sections and GOT.
             * ---------------------------------------------------------- */
            for (uint16_t i = 0; i < ctx->section_count; i++) {
                if (ctx->sections[i].exec_ptr)
                    xor_crypt((uint8_t*)ctx->sections[i].exec_ptr,
                              ctx->sections[i].exec_size, runtime_key);
            }
            for (uint32_t g = 0; g < ctx->import_count; g++)
                ctx->import_table[g] = decrypt_ptr(ctx->import_table[g], runtime_key);

            /* ----------------------------------------------------------
             * Step 4: Make the entry section executable (but not writable).
             *         All other sections retain PAGE_READWRITE for now;
             *         they may be data sections the BOF writes to.
             *         Sections that are execute+read have their protection
             *         set individually here.
             * ---------------------------------------------------------- */
#if defined(_WIN32)
            for (uint16_t i = 0; i < ctx->section_count; i++) {
                if (!ctx->sections[i].exec_ptr) continue;
                uint32_t ch = ctx->sections[i].characteristics;
                if (ch & IMAGE_SCN_MEM_EXECUTE) {
                    DWORD prot = section_prot_from_chars(ch);
                    DWORD old;
                    VirtualProtect(ctx->sections[i].exec_ptr,
                                   ctx->sections[i].exec_size,
                                   prot, &old);
                }
            }
#endif

            void (*entry)(char*, unsigned long) =
                (void(*)(char*, unsigned long))(
                    (uint8_t*)ctx->sections[si].exec_ptr + sym->Value);

            DBG("Calling '%s' at %p (timeout %u ms)", entry_name,
                (void*)entry, g_timeout_ms);

            coff_error_t run_rc = COFF_SUCCESS;

            /* ----------------------------------------------------------
             * Step 5: Execute.
             * ---------------------------------------------------------- */
#if defined(_WIN32)
            uint32_t tmo = (uint32_t)InterlockedCompareExchange(
                (LONG*)&g_timeout_ms, 0, 0);

            /*
             * Heap-allocate the args struct so it is valid for the full
             * lifetime of the thread regardless of when this stack frame
             * is reused.  A stack-allocated struct passed to CreateThread
             * is only safe if the creating thread outlives the child AND
             * does not return before the child finishes reading it —
             * WaitForSingleObject guarantees ordering but TerminateThread
             * on timeout does not.
             *
             * The CS is NOT held across the wait.  Holding it would
             * deadlock any re-entrant loader call made from inside the BOF
             * and would block CoffFree on a second concurrent BOF.
             */
            watchdog_args_t* wa = (watchdog_args_t*)malloc(sizeof(watchdog_args_t));
            if (!wa) {
                /* Allocation failed — fall back to direct call */
                entry((char*)argdata, (unsigned long)argsize);
            } else {
                wa->entry   = entry;
                wa->argdata = (char*)argdata;
                wa->argsize = (unsigned long)argsize;

                // fprintf(stderr, "[CR] before CreateThread\n"); fflush(stderr);
                HANDLE hthread = CreateThread(NULL, 0, bof_thread_proc, wa, 0, NULL);
                // fprintf(stderr, "[CR] hthread=%p\n", (void*)hthread); fflush(stderr);
                if (!hthread) {
                    /* Thread creation failed — fall back to direct call */
                    free(wa);
                    // fprintf(stderr, "[CR] direct entry call\n"); fflush(stderr);
                    entry((char*)argdata, (unsigned long)argsize);
                    // fprintf(stderr, "[CR] direct entry returned\n"); fflush(stderr);
                } else {
                    // fprintf(stderr, "[CR] waiting %u ms\n", tmo); fflush(stderr);
                    DWORD wait = WaitForSingleObject(hthread, tmo);
                    // fprintf(stderr, "[CR] wait=%lu\n", wait); fflush(stderr);
                    if (wait == WAIT_TIMEOUT) {
                        TerminateThread(hthread, 1);
                        run_rc = COFF_ERR_TIMEOUT;
                        DBG("BOF timed out after %u ms", tmo);
                    }
                    CloseHandle(hthread);
                    free(wa);
                }
            }
#else
            cs_lock();
            entry((char*)argdata, (unsigned long)argsize);
            cs_unlock();
#endif

            /* ----------------------------------------------------------
             * Steps 6-9: Re-open writable, re-encrypt, restore
             *            protections.  Done unconditionally even on timeout
             *            so we never leave plaintext executable sections.
             * ---------------------------------------------------------- */
#if defined(_WIN32)
            for (uint16_t i = 0; i < ctx->section_count; i++) {
                if (!ctx->sections[i].exec_ptr) continue;
                DWORD old;
                VirtualProtect(ctx->sections[i].exec_ptr,
                               ctx->sections[i].exec_size,
                               PAGE_READWRITE, &old);
            }
#endif
            for (uint16_t i = 0; i < ctx->section_count; i++) {
                if (ctx->sections[i].exec_ptr)
                    xor_crypt((uint8_t*)ctx->sections[i].exec_ptr,
                              ctx->sections[i].exec_size, runtime_key);
            }
            reimport_encrypt_all(ctx, runtime_key);

#if defined(_WIN32)
            /* Restore each section to its proper protection. */
            for (uint16_t i = 0; i < ctx->section_count; i++) {
                if (!ctx->sections[i].exec_ptr) continue;
                DWORD prot = section_prot_from_chars(ctx->sections[i].characteristics);
                DWORD old;
                VirtualProtect(ctx->sections[i].exec_ptr,
                               ctx->sections[i].exec_size,
                               prot, &old);
            }
#endif

            return run_rc;
        }
        sym_idx += 1 + sym->NumberOfAuxSymbols;
    }
    return COFF_ERR_ENTRY_NOT_FOUND;
}

/**
 * @brief Tear down a coff_ctx_t. Decrypts, wipes, and frees all section
 *        memory, the import GOT and cache, and finally the ctx itself.
 *        Sets *ctx_ptr to NULL.
 * @param ctx_ptr Address of the ctx pointer; safe to pass a NULL pointer
 *                or a pointer to NULL.
 */
void CoffFree(coff_ctx_t** ctx_ptr) {
    if (!ctx_ptr || !*ctx_ptr) return;
    coff_ctx_t* ctx = *ctx_ptr;
    const coff_allocator_t* alloc = &ctx->allocator;
    uint64_t key = deobfuscate_key(ctx->obfuscated_key);

    for (uint16_t s = 0; s < ctx->section_count; s++) {
        void* mem = ctx->sections[s].exec_ptr;
        if (!mem) continue;
#if defined(_WIN32)
        /* CoffApplyProtections + CoffRun leave sections in their natural
         * protection state (often PAGE_EXECUTE_READ for .text).  We have to
         * make them writable before xor_crypt and SecureZeroMemory or those
         * stores will fault. */
        {
            DWORD old;
            VirtualProtect(mem, ctx->sections[s].exec_size, PAGE_READWRITE, &old);
        }
#endif
        xor_crypt((uint8_t*)mem, ctx->sections[s].exec_size, key);
#if defined(_WIN32)
        SecureZeroMemory(mem, ctx->sections[s].exec_size);
        void* base = ctx->sections[s].base_alloc;
        if (base) {
            DWORD old;
            VirtualProtect(base, ctx->sections[s].base_size, PAGE_READWRITE, &old);
            VirtualFree(base, 0, MEM_RELEASE);
        }
#else
        memset(mem, 0, ctx->sections[s].exec_size);
        alloc->free(mem, alloc->user_ctx);
#endif
        ctx->sections[s].exec_ptr   = NULL;
        ctx->sections[s].base_alloc = NULL;
    }

    if (ctx->import_table && ctx->import_capacity > 0) {
        void* cache = ctx->import_table[ctx->import_capacity - 1];
        if (cache) {
#if defined(_WIN32)
            SecureZeroMemory(cache, ctx->import_capacity * sizeof(import_cache_entry_t));
#else
            memset(cache, 0, ctx->import_capacity * sizeof(import_cache_entry_t));
#endif
            priv_free(cache);
        }
#if defined(_WIN32)
        SecureZeroMemory(ctx->import_table, ctx->import_capacity * sizeof(void*));
#else
        memset(ctx->import_table, 0, ctx->import_capacity * sizeof(void*));
#endif
        priv_free(ctx->import_table);
        ctx->import_table = NULL;
    }

    ctx->obfuscated_key = 0;
    ctx->integrity_crc  = 0;
#if defined(_WIN32)
    SecureZeroMemory(ctx, sizeof(coff_ctx_t));
#else
    memset(ctx, 0, sizeof(coff_ctx_t));
#endif
    priv_free(ctx);
    *ctx_ptr = NULL;
}

/**
 * @brief Convenience wrapper: CoffLoad → CoffApplyProtections → CoffRun →
 *        CoffFree. Use this when you do not need to keep the ctx around
 *        between calls.
 * @param functionname Entry symbol, usually "go".
 * @param coff_data    Raw COFF bytes.
 * @param filesize     Length of coff_data.
 * @param allocator    Optional allocator override (NULL = default).
 * @param argdata      Optional argument blob.
 * @param argsize      Length of argdata.
 * @return First non-success code encountered, or COFF_SUCCESS.
 */
coff_error_t CoffRunBOF(
    const char*             functionname,
    const uint8_t*          coff_data,
    uint32_t                filesize,
    const coff_allocator_t* allocator,
    uint8_t*                argdata,
    int                     argsize)
{
    coff_ctx_t* ctx = NULL;
    coff_error_t rc = CoffLoad(coff_data, filesize, allocator, &ctx);
    // fprintf(stderr, "[H] CoffLoad rc=%d (%s)\n", rc, CoffErrorString(rc));
    // fflush(stderr);
    if (rc != COFF_SUCCESS) return rc;

    rc = CoffApplyProtections(ctx);
    // fprintf(stderr, "[H] CoffApplyProtections rc=%d (%s)\n", rc, CoffErrorString(rc));
    // fflush(stderr);
    if (rc != COFF_SUCCESS) { CoffFree(&ctx); return rc; }

    rc = CoffRun(ctx, functionname, coff_data, filesize, argdata, argsize);
    // fprintf(stderr, "[H] CoffRun rc=%d (%s)\n", rc, CoffErrorString(rc));
    // fflush(stderr);

    CoffFree(&ctx);
    return rc;
}

/**
 * @brief Human-readable string for a coff_error_t code.
 * @param err Error code.
 * @return Static string (do not free).
 */
const char* CoffErrorString(coff_error_t err) {
    switch (err) {
    case COFF_SUCCESS:                  return "Success";
    case COFF_ERR_NULL_ARG:             return "NULL argument";
    case COFF_ERR_FILE_TOO_SMALL:       return "File too small";
    case COFF_ERR_BAD_SYMTAB_OFFSET:    return "Symbol-table offset invalid";
    case COFF_ERR_SYMTAB_OVERFLOW:      return "Symbol table overflows file";
    case COFF_ERR_STRTAB_OVERFLOW:      return "String table overflows file";
    case COFF_ERR_STRTAB_SIZE_MISMATCH: return "String-table size mismatch";
    case COFF_ERR_SECTION_OVERFLOW:     return "Section header overflows file";
    case COFF_ERR_RELOC_OVERFLOW:       return "Relocation table overflows file";
    case COFF_ERR_ALLOC_FAIL:           return "Memory allocation failed";
    case COFF_ERR_SYMBOL_UNRESOLVED:    return "Unresolved external symbol";
    case COFF_ERR_RELOC_RANGE:          return "Relocation target out of 32-bit range";
    case COFF_ERR_RELOC_UNKNOWN_TYPE:   return "Unknown relocation type";
    case COFF_ERR_ENTRY_NOT_FOUND:      return "Entry-point symbol not found";
    case COFF_ERR_BAD_MACHINE:          return "Unsupported machine type";
    case COFF_ERR_SYMIDX_OOB:           return "Symbol index out of bounds";
    case COFF_ERR_RAWDATA_OVERFLOW:     return "Section raw-data overflows file";
    case COFF_ERR_CTX_CORRUPT:          return "Context integrity check failed";
    case COFF_ERR_STACK_CORRUPT:        return "Stack canary mismatch";
    case COFF_ERR_GUARD_FAULT:          return "Guard page violation";
    case COFF_ERR_TIMEOUT:              return "BOF execution timed out";
    case COFF_ERR_NOT_INITIALISED:      return "CoffLoaderInit not called";
    default:                            return "Unknown error";
    }
}

/**
 * @brief Securely wipe and free a buffer returned by getFileContents or
 *        unhexlify. Sets *buf to NULL.
 * @param buf  Address of the buffer pointer.
 * @param size Size of the buffer in bytes.
 */
void CoffFreeBlob(unsigned char** buf, uint32_t size) {
    if (!buf || !*buf) return;
#if defined(_WIN32)
    SecureZeroMemory(*buf, size);
#else
    memset(*buf, 0, size);
#endif
    free(*buf);
    *buf = NULL;
}

/**
 * @brief Decode an ASCII hex string into raw bytes.
 * @param value  NUL-terminated hex string, even length.
 * @param outlen Receives the decoded byte count.
 * @return Newly-allocated buffer (caller frees via free or CoffFreeBlob),
 *         or NULL on invalid input or allocation failure.
 */
unsigned char* unhexlify(const unsigned char* value, int* outlen) {
    if (!value || !outlen) return NULL;
    size_t slen = strlen((const char*)value);
    if (slen % 2 != 0) return NULL;
    unsigned char* out = (unsigned char*)calloc(slen / 2 + 1, 1);
    if (!out) return NULL;
    for (size_t i = 0; i < slen; i += 2) {
        char pair[3] = { (char)value[i], (char)value[i+1], '\0' };
        out[i / 2] = (unsigned char)strtol(pair, NULL, 16);
    }
    *outlen = (int)(slen / 2);
    return out;
}

/**
 * @brief Read an entire file into a heap buffer.
 * @param filepath Path to read.
 * @param outsize  Receives the file size in bytes.
 * @return Newly-allocated buffer (caller frees), or NULL on error.
 */
unsigned char* getFileContents(const char* filepath, uint32_t* outsize) {
    if (!filepath || !outsize) return NULL;
    FILE* f = fopen(filepath, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    unsigned char* buf = (unsigned char*)calloc((size_t)sz + 1, 1);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (!r) { free(buf); return NULL; }
    *outsize = (uint32_t)r;
    return buf;
}


/**
 * @brief Vectored exception handler used by the standalone harness. Logs
 *        the fault code + address for genuine CPU exceptions and
 *        terminates the process; lets other notifications fall through.
 * @param ep Exception record from the OS.
 * @return EXCEPTION_CONTINUE_SEARCH for ignored codes (the function does
 *         not return for codes it handles — it calls ExitProcess).
 */
static LONG WINAPI veh(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    // Only handle actual faults, not C++ exceptions or debug events
    if (code == EXCEPTION_ACCESS_VIOLATION ||
        code == EXCEPTION_ILLEGAL_INSTRUCTION ||
        code == EXCEPTION_STACK_OVERFLOW ||
        code == EXCEPTION_PRIV_INSTRUCTION ||
        code == EXCEPTION_IN_PAGE_ERROR) {
        fprintf(stderr, "[VEH] code=0x%08lX addr=%p\n",
                code, ep->ExceptionRecord->ExceptionAddress);
        fflush(stderr);
        FlushFileBuffers(GetStdHandle(STD_ERROR_HANDLE));
        ExitProcess(code);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* =========================================================================
 * Standalone harness  (-DCOFF_STANDALONE)
 * ========================================================================= */
#ifdef COFF_STANDALONE
/**
 * @brief Standalone test driver. Loads a BOF from disk, optionally decodes
 *        a hex-encoded argument blob, runs the BOF and prints whatever it
 *        wrote via the Beacon output API.
 *        Usage: <exe> <entry> <bof.o> [hexargs] [timeout_ms]
 * @return 0 on COFF_SUCCESS, 1 on any failure.
 */
int main(int argc, char* argv[]) {
    AddVectoredExceptionHandler(1, veh);
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)veh);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <entry> <bof.o> [hexargs] [timeout_ms]\n", argv[0]);
        return 1;
    }

    coff_error_t rc = CoffLoaderInit();
    if (rc != COFF_SUCCESS) {
        fprintf(stderr, "CoffLoaderInit: %s\n", CoffErrorString(rc));
        return 1;
    }

    if (argc >= 5) CoffSetTimeout((uint32_t)strtoul(argv[4], NULL, 10));

    uint32_t fsz = 0;
    unsigned char* data = getFileContents(argv[2], &fsz);
    if (!data) { fprintf(stderr, "Read failed\n"); CoffLoaderTeardown(); return 1; }

    int asz = 0;
    unsigned char* args = NULL;
    if (argc >= 4 && argv[3])
        args = unhexlify((const unsigned char*)argv[3], &asz);


    rc = CoffRunBOF(argv[1], data, fsz, NULL, args, asz);

    /* Zero-wipe the blob and args before freeing */
    CoffFreeBlob(&data, fsz);
    if (args) CoffFreeBlob(&args, (uint32_t)asz);

    if (rc != COFF_SUCCESS)
        fprintf(stderr, "Error: %s\n", CoffErrorString(rc));

#if defined(_WIN32)
    int outsz = 0;
    char* out = BeaconGetOutputData(&outsz);
    if (out) { printf("%.*s\n", outsz, out); free(out); }
#endif

    CoffLoaderTeardown();
    return rc == COFF_SUCCESS ? 0 : 1;
}
#endif