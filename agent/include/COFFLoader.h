#ifndef COFFLOADER_H_
#define COFFLOADER_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * COFFLoader - Production-grade Beacon Object File / COFF Loader
 * =========================================================================
 * v3 additions:
 *  - CoffLoaderInit() / CoffLoaderTeardown() for explicit lifecycle management
 *  - __C_specific_handler resolved once inside CoffLoaderInit, not per-load
 *  - CoffRun watchdog: BOF executes on a dedicated thread with configurable
 *    timeout; a hung BOF is detected and the thread is terminated cleanly
 *  - getFileContents / unhexlify zero-wipe the blob after CoffRunBOF returns
 *  - CoffResolveExport() exposed so BOFs using DYNAMIC_LIB_COUNT can call the
 *    hardened hash-based resolver instead of raw LoadLibraryA/GetProcAddress
 * ========================================================================= */

/* -----------------------------------------------------------------
 * COFF on-disk structures
 * ----------------------------------------------------------------- */
#pragma pack(push, 1)

typedef struct coff_file_header {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} coff_file_header_t;

typedef struct coff_sect {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLineNumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} coff_sect_t;

typedef struct coff_reloc {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} coff_reloc_t;

typedef struct coff_sym {
    union {
        char     Name[8];
        uint32_t value[2];
    } first;
    uint32_t Value;
    uint16_t SectionNumber;
    uint16_t Type;
    uint8_t  StorageClass;
    uint8_t  NumberOfAuxSymbols;
} coff_sym_t;

#pragma pack(pop)

/* -----------------------------------------------------------------
 * Machine types
 * ----------------------------------------------------------------- */
#define MACHINETYPE_AMD64   0x8664
#define MACHINETYPE_I386    0x014C
#define MACHINETYPE_ARM64   0xAA64

/* -----------------------------------------------------------------
 * Relocation types – AMD64
 * ----------------------------------------------------------------- */
#define IMAGE_REL_AMD64_ABSOLUTE  0x0000
#define IMAGE_REL_AMD64_ADDR64    0x0001
#define IMAGE_REL_AMD64_ADDR32    0x0002
#define IMAGE_REL_AMD64_ADDR32NB  0x0003
#define IMAGE_REL_AMD64_REL32     0x0004
#define IMAGE_REL_AMD64_REL32_1   0x0005
#define IMAGE_REL_AMD64_REL32_2   0x0006
#define IMAGE_REL_AMD64_REL32_3   0x0007
#define IMAGE_REL_AMD64_REL32_4   0x0008
#define IMAGE_REL_AMD64_REL32_5   0x0009
#define IMAGE_REL_AMD64_SECTION   0x000A
#define IMAGE_REL_AMD64_SECREL    0x000B
#define IMAGE_REL_AMD64_SECREL7   0x000C
#define IMAGE_REL_AMD64_TOKEN     0x000D
#define IMAGE_REL_AMD64_SREL32    0x000E
#define IMAGE_REL_AMD64_PAIR      0x000F
#define IMAGE_REL_AMD64_SSPAN32   0x0010

/* -----------------------------------------------------------------
 * Relocation types – i386
 * ----------------------------------------------------------------- */
#define IMAGE_REL_I386_ABSOLUTE   0x0000
#define IMAGE_REL_I386_DIR16      0x0001
#define IMAGE_REL_I386_REL16      0x0002
#define IMAGE_REL_I386_DIR32      0x0006
#define IMAGE_REL_I386_DIR32NB    0x0007
#define IMAGE_REL_I386_SEG12      0x0009
#define IMAGE_REL_I386_SECTION    0x000A
#define IMAGE_REL_I386_SECREL     0x000B
#define IMAGE_REL_I386_TOKEN      0x000C
#define IMAGE_REL_I386_SECREL7    0x000D
#define IMAGE_REL_I386_REL32      0x0014

/* -----------------------------------------------------------------
 * Section characteristic flags
 * ----------------------------------------------------------------- */
#define IMAGE_SCN_CNT_CODE               0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_DISCARDABLE        0x02000000
#define IMAGE_SCN_MEM_NOT_CACHED         0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED          0x08000000
#define IMAGE_SCN_MEM_SHARED             0x10000000
#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define IMAGE_SCN_MEM_READ               0x40000000
#define IMAGE_SCN_MEM_WRITE              0x80000000

/* -----------------------------------------------------------------
 * Symbol storage classes
 * ----------------------------------------------------------------- */
#ifndef IMAGE_SYM_CLASS_EXTERNAL
#  define IMAGE_SYM_CLASS_EXTERNAL     0x02
#endif
#ifndef IMAGE_SYM_CLASS_STATIC
#  define IMAGE_SYM_CLASS_STATIC       0x03
#endif
#ifndef IMAGE_SYM_CLASS_EXTERNAL_DEF
#  define IMAGE_SYM_CLASS_EXTERNAL_DEF 0x05
#endif
#ifndef IMAGE_SYM_CLASS_LABEL
#  define IMAGE_SYM_CLASS_LABEL        0x06
#endif
#ifndef IMAGE_SYM_CLASS_SECTION
#  define IMAGE_SYM_CLASS_SECTION 0x0068
#endif

/* -----------------------------------------------------------------
 * Error codes
 * ----------------------------------------------------------------- */
typedef enum {
    COFF_SUCCESS                  =  0,
    COFF_ERR_NULL_ARG             = -1,
    COFF_ERR_FILE_TOO_SMALL       = -2,
    COFF_ERR_BAD_SYMTAB_OFFSET    = -3,
    COFF_ERR_SYMTAB_OVERFLOW      = -4,
    COFF_ERR_STRTAB_OVERFLOW      = -5,
    COFF_ERR_STRTAB_SIZE_MISMATCH = -6,
    COFF_ERR_SECTION_OVERFLOW     = -7,
    COFF_ERR_RELOC_OVERFLOW       = -8,
    COFF_ERR_ALLOC_FAIL           = -9,
    COFF_ERR_SYMBOL_UNRESOLVED    = -10,
    COFF_ERR_RELOC_RANGE          = -11,
    COFF_ERR_RELOC_UNKNOWN_TYPE   = -12,
    COFF_ERR_ENTRY_NOT_FOUND      = -13,
    COFF_ERR_BAD_MACHINE          = -14,
    COFF_ERR_SYMIDX_OOB           = -15,
    COFF_ERR_RAWDATA_OVERFLOW     = -16,
    COFF_ERR_CTX_CORRUPT          = -17,
    COFF_ERR_STACK_CORRUPT        = -18,
    COFF_ERR_GUARD_FAULT          = -19,
    COFF_ERR_TIMEOUT              = -20,   /* BOF exceeded watchdog deadline */
    COFF_ERR_NOT_INITIALISED      = -21,   /* CoffLoaderInit not called       */
} coff_error_t;

const char* CoffErrorString(coff_error_t err);

/* -----------------------------------------------------------------
 * Default BOF execution timeout (milliseconds).
 * Override: CoffSetTimeout(ms) before calling CoffRun / CoffRunBOF.
 * Set to INFINITE (0xFFFFFFFF) to disable the watchdog.
 * ----------------------------------------------------------------- */
#define COFF_DEFAULT_TIMEOUT_MS  30000u

/* -----------------------------------------------------------------
 * Allocator back-end
 * ----------------------------------------------------------------- */
typedef void* (*coff_alloc_fn)(size_t size, void* user_ctx);
typedef void  (*coff_free_fn)(void*  ptr,   void* user_ctx);

typedef struct {
    coff_alloc_fn alloc;
    coff_free_fn  free;
    void*         user_ctx;
} coff_allocator_t;

extern const coff_allocator_t g_coff_default_allocator;

/* -----------------------------------------------------------------
 * Section allocation record (one per COFF section)
 * ----------------------------------------------------------------- */
typedef struct {
    void*    base_alloc;      /* raw VirtualAlloc base (before leading guard) */
    size_t   base_size;       /* total raw allocation size inc. guard pages   */
    void*    exec_ptr;        /* usable section memory                        */
    uint32_t exec_size;
    uint32_t characteristics;
} coff_section_t;

/* -----------------------------------------------------------------
 * Loader context
 * ----------------------------------------------------------------- */
#define COFF_MAX_SECTIONS 96

typedef struct {
    coff_section_t   sections[COFF_MAX_SECTIONS];
    uint16_t         section_count;

    void**           import_table;
    uint32_t         import_count;
    uint32_t         import_capacity;

    uint64_t         obfuscated_key;  /* runtime XOR key, stored rotated    */
    uint32_t         integrity_crc;   /* CRC32 over immutable ctx fields    */

    void*            private_heap;    /* HANDLE to isolated loader heap     */

    coff_allocator_t allocator;
    bool             protections_applied;

    /* Per-section next-trampoline offset (in slack between SizeOfRawData
     * and exec_size).  Reset in CoffLoad before the relocation pass so
     * multiple BOFs sharing one process don't step on each other. */
    uint32_t         tramp_next[COFF_MAX_SECTIONS];
} coff_ctx_t;

/* -----------------------------------------------------------------
 * Lifecycle management
 * ----------------------------------------------------------------- */

/**
 * CoffLoaderInit  –  must be called once before any other API.
 *   Initialises the private heap, critical section, and resolves
 *   __C_specific_handler into InternalFunctions[29].
 */
coff_error_t CoffLoaderInit(void);

/**
 * CoffLoaderTeardown  –  call on agent shutdown.
 *   Destroys the private heap, deletes the critical section.
 *   All ctx handles must have been freed before calling this.
 */
void CoffLoaderTeardown(void);

/**
 * CoffSetTimeout  –  override the per-BOF watchdog deadline.
 *   @param ms  Timeout in milliseconds. INFINITE disables the watchdog.
 */
void CoffSetTimeout(uint32_t ms);

/* -----------------------------------------------------------------
 * Public loader API
 * ----------------------------------------------------------------- */

coff_error_t CoffLoad(
    const uint8_t*          coff_data,
    uint32_t                filesize,
    const coff_allocator_t* allocator,
    coff_ctx_t**            ctx_out);

coff_error_t CoffApplyProtections(coff_ctx_t* ctx);

coff_error_t CoffRun(
    coff_ctx_t*    ctx,
    const char*    functionname,
    const uint8_t* coff_data,
    uint32_t       filesize,
    uint8_t*       argdata,
    int            argsize);

void CoffFree(coff_ctx_t** ctx);

coff_error_t CoffRunBOF(
    const char*             functionname,
    const uint8_t*          coff_data,
    uint32_t                filesize,
    const coff_allocator_t* allocator,
    uint8_t*                argdata,
    int                     argsize);

/**
 * CoffResolveExport  –  hash-based DLL export resolver.
 *   Exposed so BOFs using DYNAMIC_LIB_COUNT can call the hardened
 *   resolver instead of raw LoadLibraryA / GetProcAddress.
 *
 *   @param lib_name   DLL name as passed to LoadLibraryA (e.g. "NTDLL")
 *   @param func_name  Export function name
 *   @return Function pointer, or NULL on failure.
 */
void* CoffResolveExport(const char* lib_name, const char* func_name);

/* -----------------------------------------------------------------
 * Utilities
 * ----------------------------------------------------------------- */
unsigned char* unhexlify(const unsigned char* value, int* outlen);
unsigned char* getFileContents(const char* filepath, uint32_t* outsize);

#ifdef __cplusplus
}
#endif

#endif /* COFFLOADER_H_ */