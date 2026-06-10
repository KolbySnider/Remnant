/*
 * base.c  –  BOF runtime helpers
 *
 * Compiled into every BOF, not into the loader.
 *
 * Changes from original TrustedSec base.c
 * ─────────────────────────────────────────
 * [INCLUDE]  bofdefs.h → beacon_compatibility.h
 *
 * [BUG]  internal_printf: transferBuffer was allocated but the memset reset
 *        used `transfersize` instead of `bufsize`, leaving stale bytes in the
 *        buffer on the next iteration.  Fixed to memset the full bufsize.
 *
 * [BUG]  internal_printf: transferBuffer was leaked if vsnprintf returned -1
 *        (encoding failure) because the early return fired after allocation.
 *        Moved the allocation past the early return.
 *
 * [BUG]  internal_printf: intBuffer null-check was missing before memcpy;
 *        added guard.
 *
 * [DYNRES] DynamicLoad: when DYNAMIC_LIB_COUNT is defined, DynamicLoad now
 *          calls CoffResolveExport() (the loader's hardened hash-based
 *          resolver) instead of raw LoadLibraryA / GetProcAddress, avoiding
 *          plaintext DLL name strings in the BOF's memory.  Falls back to
 *          LoadLibraryA only when the loader resolver returns NULL (e.g.
 *          not running inside the hardened loader).
 */

#include <windows.h>
#include "beacon_compatibility.h"

#ifndef bufsize
#  define bufsize 8192
#endif

/* These three globals live in .data (not .bss) because the COFF loader's
 * reference implementation does not handle .bss sections correctly. */
char*  output         __attribute__((section(".data"))) = 0;
WORD   currentoutsize __attribute__((section(".data"))) = 0;
HANDLE trash          __attribute__((section(".data"))) = NULL;

#ifdef BOF
int   bofstart(void);
void  internal_printf(const char* format, ...);
void  printoutput(BOOL done);
#endif

char* Utf16ToUtf8(const wchar_t* input);

/* =========================================================================
 * BOF-mode implementations
 * ========================================================================= */
#ifdef BOF

int bofstart(void) {
    output        = (char*)MSVCRT$calloc(bufsize, 1);
    currentoutsize = 0;
    return output != NULL;
}

void internal_printf(const char* format, ...) {
    int       buffersize  = 0;
    int       transfersize = 0;
    char*     curloc      = NULL;
    char*     intBuffer   = NULL;
    va_list   args;

    /* Calculate required buffer size first */
    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);

    /* vsnprintf returns -1 on encoding failure (e.g. non-Latin wide chars) */
    if (buffersize <= 0)
        return;

    /* Allocate after the early-return check so we never leak on failure */
    char* transferBuffer = (char*)intAlloc(bufsize);
    if (!transferBuffer)
        return;

    intBuffer = (char*)intAlloc(buffersize + 1);
    if (!intBuffer) {
        intFree(transferBuffer);
        return;
    }

    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize + 1, format, args);
    va_end(args);

    if (buffersize + currentoutsize < bufsize) {
        /* Fits in the current output buffer – just append */
        memcpy(output + currentoutsize, intBuffer, buffersize);
        currentoutsize += (WORD)buffersize;
    } else {
        /* Overflows – flush in chunks */
        curloc = intBuffer;
        while (buffersize > 0) {
            transfersize = bufsize - currentoutsize;
            if (buffersize < transfersize)
                transfersize = buffersize;

            memcpy(output + currentoutsize, curloc, transfersize);
            currentoutsize += (WORD)transfersize;

            if (currentoutsize == bufsize)
                printoutput(FALSE);   /* flush; resets currentoutsize to 0 */

            /* Reset the full transfer buffer, not just `transfersize` bytes.
             * Original bug: memset(transferBuffer, 0, transfersize) left
             * stale bytes visible on the next iteration. */
            memset(transferBuffer, 0, bufsize);

            curloc     += transfersize;
            buffersize -= transfersize;
        }
    }

    intFree(intBuffer);
    intFree(transferBuffer);
}

void printoutput(BOOL done) {
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    memset(output, 0, bufsize);
    if (done) {
        MSVCRT$free(output);
        output = NULL;
    }
}

/* =========================================================================
 * DYNAMIC_LIB_COUNT support
 * =========================================================================
 * When a BOF declares #define DYNAMIC_LIB_COUNT N before including base.c,
 * DynamicLoad is available for runtime function resolution.
 *
 * Uses CoffResolveExport() from the loader (hash-based, no string artifacts)
 * with a fallback to LoadLibraryA / GetProcAddress for environments where
 * the hardened loader is not in use.
 * ========================================================================= */
#ifdef DYNAMIC_LIB_COUNT

typedef struct loadedLibrary {
    HMODULE     hMod;
    const char* name;   /* must be a string constant – not freed by bofstop */
} loadedLibrary, *ploadedLibrary;

loadedLibrary loadedLibraries[DYNAMIC_LIB_COUNT]
    __attribute__((section(".data"))) = {0};
DWORD loadedLibrariesCount
    __attribute__((section(".data"))) = 0;

/* Simple string equality without CRT strcmp (which may not be resolved) */
static BOOL bof_streq(LPCSTR a, LPCSTR b) {
    while (*a && *b) {
        if (*a++ != *b++) return FALSE;
    }
    return (*a == '\0' && *b == '\0');
}

/*
 * DynamicLoad
 *
 * szLibrary  – DLL name, normalised to UPPERCASE (e.g. "NTDLL")
 * szFunction – exported function name
 *
 * Returns a FARPROC on success, NULL on failure.
 */
FARPROC DynamicLoad(const char* szLibrary, const char* szFunction) {
    HMODULE hMod = NULL;
    FARPROC fp   = NULL;

    /* Check the already-loaded table first */
    for (DWORD i = 0; i < loadedLibrariesCount; i++) {
        if (bof_streq(szLibrary, loadedLibraries[i].name)) {
            hMod = loadedLibraries[i].hMod;
            break;
        }
    }

    /* Try the hardened loader resolver first (avoids LoadLibraryA string) */
    fp = (FARPROC)CoffResolveExport(szLibrary, szFunction);
    if (fp)
        return fp;

    /* Fallback: load the library if not already present */
    if (!hMod) {
        hMod = LoadLibraryA(szLibrary);
        if (!hMod) {
            BeaconPrintf(CALLBACK_ERROR,
                "*** DynamicLoad: LoadLibraryA(%s) failed\n", szLibrary);
            return NULL;
        }
        if (loadedLibrariesCount < DYNAMIC_LIB_COUNT) {
            loadedLibraries[loadedLibrariesCount].hMod  = hMod;
            loadedLibraries[loadedLibrariesCount].name  = szLibrary;
            loadedLibrariesCount++;
        }
    }

    fp = GetProcAddress(hMod, szFunction);
    if (!fp) {
        BeaconPrintf(CALLBACK_ERROR,
            "*** DynamicLoad: GetProcAddress(%s) failed\n", szFunction);
    }
    return fp;
}

#endif /* DYNAMIC_LIB_COUNT */

/* =========================================================================
 * bofstop  –  release libraries loaded via DynamicLoad
 * ========================================================================= */
void bofstop(void) {
#ifdef DYNAMIC_LIB_COUNT
    for (DWORD i = 0; i < loadedLibrariesCount; i++) {
        if (loadedLibraries[i].hMod)
            FreeLibrary(loadedLibraries[i].hMod);
    }
    loadedLibrariesCount = 0;
#endif
}

/* =========================================================================
 * Non-BOF mode (standalone unit-test builds)
 * ========================================================================= */
#else  /* !BOF */

#define internal_printf  printf
#define printoutput(x)   ((void)0)
#define bofstart()       (1)
#define bofstop()        ((void)0)

#endif /* BOF */

/* =========================================================================
 * Utf16ToUtf8  –  available in both BOF and non-BOF builds
 * ========================================================================= */
char* Utf16ToUtf8(const wchar_t* input) {
    if (!input) return NULL;

    int ret = Kernel32$WideCharToMultiByte(
        CP_UTF8, 0, input, -1, NULL, 0, NULL, NULL);
    if (ret <= 0) return NULL;

    char* newString = (char*)intAlloc((size_t)ret);
    if (!newString) return NULL;

    ret = Kernel32$WideCharToMultiByte(
        CP_UTF8, 0, input, -1, newString, ret, NULL, NULL);
    if (ret == 0) {
        intFree(newString);
        return NULL;
    }
    return newString;
}