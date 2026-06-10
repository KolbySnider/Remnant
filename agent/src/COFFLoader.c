/*
 * COFFLoader.c  –  Production-grade BOF/COFF Loader (v3)
 *
 * v3 additions over v2
 * ─────────────────────
 * [INIT]    CoffLoaderInit() / CoffLoaderTeardown() provide an explicit
 *           process lifecycle.  The private heap and CS are created/destroyed
 *           here instead of lazily, giving clean shutdown semantics.
 *
 * [CSH]     __C_specific_handler is resolved once in CoffLoaderInit() via
 *           GetProcAddress and stored in InternalFunctions[29].  Previously
 *           it was never set in the hardened loader, causing SEH to crash.
 *
 * [WATCH]   CoffRun() executes the BOF entry point on a dedicated thread.
 *           WaitForSingleObject with a configurable deadline detects a hung
 *           BOF and terminates the thread, returning COFF_ERR_TIMEOUT.
 *           Default timeout: COFF_DEFAULT_TIMEOUT_MS (30 s).
 *
 * [WIPE]    getFileContents() and unhexlify() zero-wipe their output buffers
 *           via a companion CoffFreeBlob() so the caller can erase the COFF
 *           blob from memory after CoffRunBOF returns.
 *
 * [DYNRES]  CoffResolveExport() exposes the hardened hash-based resolver so
 *           BOFs using DYNAMIC_LIB_COUNT / DynamicLoad can call it instead of
 *           raw LoadLibraryA / GetProcAddress, avoiding string artifacts.
 */

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

static void cs_lock(void)   { EnterCriticalSection(&g_cs); }
static void cs_unlock(void) { LeaveCriticalSection(&g_cs); }

static void* priv_alloc(size_t sz) {
    if (!g_private_heap) return NULL;
    if (sz == 0) sz = 1;
    return HeapAlloc(g_private_heap, HEAP_ZERO_MEMORY, sz);
}
static void priv_free(void* p) {
    if (p && g_private_heap) HeapFree(g_private_heap, 0, p);
}

#else
/* Non-Windows stubs */
static volatile uint32_t g_timeout_ms = COFF_DEFAULT_TIMEOUT_MS;
#define REQUIRE_INIT()      ((void)0)
#define REQUIRE_INIT_VOID() ((void)0)
static void cs_lock(void)   {}
static void cs_unlock(void) {}
static void* priv_alloc(size_t sz) { return calloc(1, sz ? sz : 1); }
static void  priv_free(void* p)    { free(p); }
#endif

/* =========================================================================
 * CoffLoaderInit
 * ========================================================================= */
coff_error_t CoffLoaderInit(void) {
#if defined(_WIN32)
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

    InitializeCriticalSectionAndSpinCount(&g_cs, 4000);

    /* Resolve __C_specific_handler once here so every BOF that uses SEH
     * gets a valid pointer.  This is the only place we call GetProcAddress
     * with a string for an internal function. */
    HMODULE hntdll = GetModuleHandleA("ntdll.dll");
    HMODULE hkern  = GetModuleHandleA("kernel32.dll");
    /* __C_specific_handler lives in ntdll on x64, kernel32 on x86 */
    FARPROC csh = NULL;
    if (hntdll) csh = GetProcAddress(hntdll,  "__C_specific_handler");
    if (!csh && hkern) csh = GetProcAddress(hkern, "__C_specific_handler");
    /* Store into the compatibility table */
    extern unsigned char* InternalFunctions[30][2];
    InternalFunctions[29][1] = (unsigned char*)(void*)csh;

    InterlockedExchange(&g_loader_ready, 2);
    return COFF_SUCCESS;
#else
    return COFF_SUCCESS;
#endif
}

/* =========================================================================
 * CoffLoaderTeardown
 * ========================================================================= */
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

/* =========================================================================
 * CoffSetTimeout
 * ========================================================================= */
void CoffSetTimeout(uint32_t ms) {
#if defined(_WIN32)
    InterlockedExchange((LONG*)&g_timeout_ms, (LONG)ms);
#else
    g_timeout_ms = ms;
#endif
}

/* =========================================================================
 * Runtime key derivation
 * ========================================================================= */
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

static uint64_t obfuscate_key(uint64_t k)   { return (k >> 13) | (k << 51); }
static uint64_t deobfuscate_key(uint64_t o) { return (o << 13) | (o >> 51); }

/* =========================================================================
 * Keystream cipher (xorshift64-based)
 * ========================================================================= */
static void xor_crypt(uint8_t* buf, size_t len, uint64_t key) {
    uint64_t ks = key;
    for (size_t i = 0; i < len; i++) {
        ks ^= ks >> 12; ks ^= ks << 25; ks ^= ks >> 27;
        buf[i] ^= (uint8_t)(ks & 0xFF);
    }
}

static void* encrypt_ptr(void* p, uint64_t key) {
    uint64_t ks = key;
    ks ^= ks >> 12; ks ^= ks << 25; ks ^= ks >> 27;
    return (void*)((uintptr_t)p ^ (uintptr_t)(ks * 0x2545F4914F6CDD1DULL));
}
#define decrypt_ptr encrypt_ptr

/* =========================================================================
 * CRC32 for ctx integrity
 * ========================================================================= */
static uint32_t crc32_byte(uint32_t c, uint8_t b) {
    c ^= b;
    for (int i = 0; i < 8; i++) c = (c >> 1) ^ (0xEDB88320u & -(c & 1u));
    return c;
}
static uint32_t crc32_buf(const void* p, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) c = crc32_byte(c, ((const uint8_t*)p)[i]);
    return c ^ 0xFFFFFFFFu;
}
static uint32_t ctx_crc(const coff_ctx_t* ctx) {
    uint32_t f[3] = { ctx->section_count, ctx->import_capacity,
                      (uint32_t)(ctx->obfuscated_key & 0xFFFFFFFFu) };
    return crc32_buf(f, sizeof(f));
}
static coff_error_t ctx_check(const coff_ctx_t* ctx) {
    if (!ctx) return COFF_ERR_NULL_ARG;
    return ctx_crc(ctx) == ctx->integrity_crc ? COFF_SUCCESS : COFF_ERR_CTX_CORRUPT;
}

/* =========================================================================
 * Hash functions
 * ========================================================================= */
static uint32_t djb2(const char* s) {
    uint32_t h = 5381;
    for (; *s; s++) h = ((h << 5) + h) ^ (uint8_t)*s;
    return h;
}
static uint32_t djb2_lower(const char* s) {
    uint32_t h = 5381;
    for (; *s; s++) {
        uint8_t c = (uint8_t)*s;
        if (c >= 'A' && c <= 'Z') c |= 0x20;
        h = ((h << 5) + h) ^ c;
    }
    return h;
}

/* =========================================================================
 * Default section allocator (guard pages, no MEM_TOP_DOWN)
 * ========================================================================= */
static void* default_alloc(size_t size, void* user_ctx) {
    (void)user_ctx;
#if defined(_WIN32)
    size_t total = PAGE_SIZE_BYTES + size + PAGE_SIZE_BYTES;
    uint8_t* base = (uint8_t*)VirtualAlloc(NULL, total,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_READWRITE);
    if (!base) return NULL;
    DWORD old;
    VirtualProtect(base,                          PAGE_SIZE_BYTES, PAGE_NOACCESS, &old);
    VirtualProtect(base + PAGE_SIZE_BYTES + size, PAGE_SIZE_BYTES, PAGE_NOACCESS, &old);
    return base + PAGE_SIZE_BYTES;
#else
    return calloc(1, size);
#endif
}
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

/* =========================================================================
 * Hash-based PE export resolution (no plaintext GetProcAddress)
 * ========================================================================= */
#if defined(_WIN32)
static void* find_export_by_hash(HMODULE hmod, uint32_t func_hash) {
    if (!hmod) return NULL;
    uint8_t* base = (uint8_t*)hmod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    DWORD exp_rva = nt->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return NULL;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + exp_rva);
    DWORD* names  = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords   = (WORD*) (base + exp->AddressOfNameOrdinals);
    DWORD* funcs  = (DWORD*)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (djb2((const char*)(base + names[i])) == func_hash)
            return (void*)(base + funcs[ords[i]]);
    }
    return NULL;
}

static HMODULE find_module_by_hash(uint32_t dll_hash) {
#ifdef _WIN64
    PEB* peb = (PEB*)__readgsqword(0x60);
#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* cur  = head->Flink;
    while (cur != head) {
        LDR_DATA_TABLE_ENTRY* e = CONTAINING_RECORD(
            cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (e->BaseDllName.Buffer) {
            char narrow[64] = {0};
            int  n = e->BaseDllName.Length / 2;
            if (n >= (int)sizeof(narrow)) n = (int)sizeof(narrow) - 1;
            for (int i = 0; i < n; i++) narrow[i] = (char)e->BaseDllName.Buffer[i];
            if (djb2_lower(narrow) == dll_hash)
                return (HMODULE)e->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}
#endif /* _WIN32 */

/* =========================================================================
 * CoffResolveExport  –  public hardened resolver
 * =========================================================================
 * Called by base.c DynamicLoad replacement and by the loader's own
 * symbol-resolution path.
 * ========================================================================= */
void* CoffResolveExport(const char* lib_name, const char* func_name) {
    if (!lib_name || !func_name) return NULL;
#if defined(_WIN32)
    uint32_t lib_hash  = djb2_lower(lib_name);
    uint32_t func_hash = djb2(func_name);

    HMODULE hmod = find_module_by_hash(lib_hash);
    if (!hmod) {
        /* LoadLibraryA unavoidable for not-yet-loaded DLLs; name is
         * stack-local and gone the moment this call returns. */
        hmod = LoadLibraryA(lib_name);
        if (!hmod) return NULL;
    }
    void* fp = find_export_by_hash(hmod, func_hash);
    /* Fallback for forwarded exports, which don't appear in the EAT */
    if (!fp) fp = (void*)GetProcAddress(hmod, func_name);
    return fp;
#else
    return NULL;
#endif
}

/* =========================================================================
 * Internal symbol resolution
 * ========================================================================= */
static bool str_pfx(const char* s, const char* p) {
    return strncmp(s, p, strlen(p)) == 0;
}

static void* resolve_symbol(const char* sym) {
    if (!sym) return NULL;

    /* Beacon / internal functions */
    if (str_pfx(sym, IMPORT_PREFIX "Beacon")        ||
        str_pfx(sym, IMPORT_PREFIX "toWideChar")    ||
        str_pfx(sym, IMPORT_PREFIX "GetProcAddress")||
        str_pfx(sym, IMPORT_PREFIX "LoadLibraryA")  ||
        str_pfx(sym, IMPORT_PREFIX "GetModuleHandleA")||
        str_pfx(sym, IMPORT_PREFIX "FreeLibrary")   ||
        strcmp(sym, "__C_specific_handler") == 0) {

        if (strcmp(sym, "__C_specific_handler") == 0)
            return InternalFunctions[29][1];

        const char* bare = sym + IMPORT_PREFIX_LEN;
        for (int i = 0; i < 30; i++) {
            if (InternalFunctions[i][0] &&
                str_pfx(bare, (char*)InternalFunctions[i][0]))
                return InternalFunctions[i][1];
        }
        return NULL;
    }

    /* DLL$Function external symbols */
    if (!str_pfx(sym, IMPORT_PREFIX)) return NULL;

    char buf[256];
    strncpy(buf, sym + IMPORT_PREFIX_LEN, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char* dollar = strchr(buf, '$');
    if (!dollar) return NULL;
    *dollar = '\0';
    char* func = dollar + 1;
    char* at   = strchr(func, '@');
    if (at) *at = '\0';

    DBG("resolve lib='%s' func='%s'", buf, func);
    return CoffResolveExport(buf, func);
}

/* =========================================================================
 * Import cache helpers
 * ========================================================================= */
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

/* =========================================================================
 * CoffLoad
 * ========================================================================= */
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

        ctx->sections[s].exec_ptr       = mem;
        ctx->sections[s].exec_size      = alloc_sz;
        ctx->sections[s].characteristics = sh->Characteristics;
#if defined(_WIN32)
        if (alloc->alloc == default_alloc) {
            ctx->sections[s].base_alloc = (uint8_t*)mem - PAGE_SIZE_BYTES;
            ctx->sections[s].base_size  = PAGE_SIZE_BYTES + alloc_sz + PAGE_SIZE_BYTES;
        } else {
            ctx->sections[s].base_alloc = mem;
            ctx->sections[s].base_size  = alloc_sz;
        }
#else
        ctx->sections[s].base_alloc = mem;
        ctx->sections[s].base_size  = alloc_sz;
#endif
    }
    ctx->section_count = hdr->NumberOfSections;

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
                void** cached = find_cached_import(ctx, sym_name, runtime_key);
                if (cached) { target = cached; }
                else {
                    void* resolved = resolve_symbol(sym_name);
                    if (!resolved) { DBG("Unresolved: %s", sym_name); RELOC_FAIL(COFF_ERR_SYMBOL_UNRESOLVED); }
                    void** slot = add_cached_import(ctx, sym_name, resolved, runtime_key);
                    if (!slot) RELOC_FAIL(COFF_ERR_ALLOC_FAIL);
                    target = slot;
                }
            } else { RELOC_FAIL(COFF_ERR_SYMBOL_UNRESOLVED); }

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

/* =========================================================================
 * CoffApplyProtections
 * ========================================================================= */
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
        bool exec     = (ch & IMAGE_SCN_MEM_EXECUTE)    != 0;
        bool write    = (ch & IMAGE_SCN_MEM_WRITE)      != 0;
        bool read     = (ch & IMAGE_SCN_MEM_READ)       != 0;
        bool discard  = (ch & IMAGE_SCN_MEM_DISCARDABLE)!= 0;
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

/* =========================================================================
 * Watchdog thread context
 * ========================================================================= */
#if defined(_WIN32)
typedef struct {
    void   (*entry)(char*, unsigned long);
    char*    argdata;
    unsigned long argsize;
} watchdog_args_t;

static DWORD WINAPI bof_thread_proc(LPVOID param) {
    watchdog_args_t* a = (watchdog_args_t*)param;
    a->entry(a->argdata, a->argsize);
    return 0;
}
#endif

/* =========================================================================
 * CoffRun
 * ========================================================================= */
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

            /* Decrypt all sections and GOT before execution */
            for (uint16_t i = 0; i < ctx->section_count; i++) {
                if (ctx->sections[i].exec_ptr)
                    xor_crypt((uint8_t*)ctx->sections[i].exec_ptr,
                              ctx->sections[i].exec_size, runtime_key);
            }
            for (uint32_t g = 0; g < ctx->import_count; g++)
                ctx->import_table[g] = decrypt_ptr(ctx->import_table[g], runtime_key);

            void (*entry)(char*, unsigned long) =
                (void(*)(char*, unsigned long))(
                    (uint8_t*)ctx->sections[si].exec_ptr + sym->Value);

            DBG("Calling '%s' at %p (timeout %u ms)", entry_name,
                (void*)entry, g_timeout_ms);

            coff_error_t run_rc = COFF_SUCCESS;

#if defined(_WIN32)
            uint32_t tmo = (uint32_t)InterlockedCompareExchange(
                (LONG*)&g_timeout_ms, 0, 0);

            watchdog_args_t wa = { entry, (char*)argdata, (unsigned long)argsize };

            cs_lock();
            HANDLE hthread = CreateThread(NULL, 0, bof_thread_proc, &wa, 0, NULL);
            if (!hthread) {
                cs_unlock();
                /* Thread creation failed – fall back to direct call */
                entry((char*)argdata, (unsigned long)argsize);
            } else {
                DWORD wait = WaitForSingleObject(hthread, tmo);
                if (wait == WAIT_TIMEOUT) {
                    TerminateThread(hthread, 1);
                    run_rc = COFF_ERR_TIMEOUT;
                    DBG("BOF timed out after %u ms", tmo);
                }
                CloseHandle(hthread);
                cs_unlock();
            }
#else
            cs_lock();
            entry((char*)argdata, (unsigned long)argsize);
            cs_unlock();
#endif

            /* Re-encrypt everything regardless of timeout */
            for (uint16_t i = 0; i < ctx->section_count; i++) {
                if (ctx->sections[i].exec_ptr)
                    xor_crypt((uint8_t*)ctx->sections[i].exec_ptr,
                              ctx->sections[i].exec_size, runtime_key);
            }
            reimport_encrypt_all(ctx, runtime_key);

            return run_rc;
        }
        sym_idx += 1 + sym->NumberOfAuxSymbols;
    }
    return COFF_ERR_ENTRY_NOT_FOUND;
}

/* =========================================================================
 * CoffFree
 * ========================================================================= */
void CoffFree(coff_ctx_t** ctx_ptr) {
    if (!ctx_ptr || !*ctx_ptr) return;
    coff_ctx_t* ctx = *ctx_ptr;
    const coff_allocator_t* alloc = &ctx->allocator;
    uint64_t key = deobfuscate_key(ctx->obfuscated_key);

    for (uint16_t s = 0; s < ctx->section_count; s++) {
        void* mem = ctx->sections[s].exec_ptr;
        if (!mem) continue;
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
        ctx->sections[s].exec_ptr = NULL;
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

/* =========================================================================
 * CoffRunBOF
 * ========================================================================= */
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
    if (rc != COFF_SUCCESS) return rc;
    rc = CoffApplyProtections(ctx);
    if (rc != COFF_SUCCESS) { CoffFree(&ctx); return rc; }
    rc = CoffRun(ctx, functionname, coff_data, filesize, argdata, argsize);
    CoffFree(&ctx);
    return rc;
}

/* =========================================================================
 * Error strings
 * ========================================================================= */
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

/* =========================================================================
 * Utilities
 * =========================================================================
 * Both functions return heap memory.  Call CoffFreeBlob() to zero-wipe
 * and free the buffer when done — do not call plain free().
 * ========================================================================= */
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

/* =========================================================================
 * Standalone harness  (-DCOFF_STANDALONE)
 * ========================================================================= */
#ifdef COFF_STANDALONE
int main(int argc, char* argv[]) {
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