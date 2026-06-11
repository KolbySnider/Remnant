/*
 * base.c  –  BOF runtime helpers
 *
 * Compiled into every BOF via #include "base.c".
 *
 * Changes from hardened v1
 * ─────────────────────────
 * [THUNKS]  MSVCRT$calloc / MSVCRT$vsnprintf / MSVCRT$free / MSVCRT$free are
 *           now resolved through the macros in beacon_compatibility.h which
 *           map them to the real CRT calls when running in the standalone
 *           loader.  No code change required here — the macros do the work —
 *           but this comment documents the dependency explicitly.
 *
 * [BOFSTART] go() in every BOF MUST call bofstart() before any
 *            internal_printf / printoutput, and bofstop() before returning.
 *            A template comment block is provided at the bottom of this file.
 *            Failure to call bofstart() means `output` is NULL and the first
 *            memcpy in internal_printf crashes with an access violation.
 *
 * [GUARD]   internal_printf: added NULL check on `output` so a missing
 *           bofstart() call produces a silent no-op rather than a crash.
 *           The correct fix is always to call bofstart(), but the guard
 *           prevents a crash in the loader harness during development.
 *
 * [BUFSIZE] bufsize default raised to 8192 to match typical CS behaviour.
 */

#include <windows.h>
#include "beacon_compatibility.h"

#ifndef bufsize
#  define bufsize 8192
#endif

/*
 * These globals live in .data (not .bss).  The COFF loader zero-initialises
 * .bss-equivalent sections during CoffLoad, but keeping them in .data is the
 * safer option for compatibility with loader implementations that do not.
 */
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
    /*
     * MSVCRT$calloc expands to calloc() via beacon_compatibility.h when
     * running in the standalone loader.  Inside a real Beacon it is
     * resolved through the Beacon's own import table.
     */
    output         = (char*)MSVCRT$calloc(bufsize, 1);
    currentoutsize = 0;
    return output != NULL;
}

void internal_printf(const char* format, ...) {
    int       buffersize   = 0;
    int       transfersize = 0;
    char*     curloc       = NULL;
    char*     intBuffer    = NULL;
    char*     transferBuffer = NULL;
    va_list   args;

    /*
     * Guard: if bofstart() was never called output is NULL.
     * Return silently rather than crashing — but the caller should fix
     * the root cause by calling bofstart() at the top of go().
     */
    if (!output) return;

    /* Calculate required buffer size first */
    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);

    /* vsnprintf returns -1 on encoding failure */
    if (buffersize <= 0)
        return;

    /* Allocate after the early-return check – never leak on failure */
    transferBuffer = (char*)intAlloc(bufsize);
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
        /* Fits in the current output buffer */
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
                printoutput(FALSE);

            /* Zero the full transfer buffer, not just transfersize bytes */
            memset(transferBuffer, 0, bufsize);

            curloc     += transfersize;
            buffersize -= transfersize;
        }
    }

    intFree(intBuffer);
    intFree(transferBuffer);
}

void printoutput(BOOL done) {
    if (!output) return;
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
 * ========================================================================= */
#ifdef DYNAMIC_LIB_COUNT

typedef struct loadedLibrary {
    HMODULE     hMod;
    const char* name;
} loadedLibrary, *ploadedLibrary;

loadedLibrary loadedLibraries[DYNAMIC_LIB_COUNT]
    __attribute__((section(".data"))) = {0};
DWORD loadedLibrariesCount
    __attribute__((section(".data"))) = 0;

static BOOL bof_streq(LPCSTR a, LPCSTR b) {
    while (*a && *b) {
        if (*a++ != *b++) return FALSE;
    }
    return (*a == '\0' && *b == '\0');
}

FARPROC DynamicLoad(const char* szLibrary, const char* szFunction) {
    HMODULE hMod = NULL;
    FARPROC fp   = NULL;

    for (DWORD i = 0; i < loadedLibrariesCount; i++) {
        if (bof_streq(szLibrary, loadedLibraries[i].name)) {
            hMod = loadedLibraries[i].hMod;
            break;
        }
    }

    /* Try hardened resolver first */
    fp = (FARPROC)CoffResolveExport(szLibrary, szFunction);
    if (fp)
        return fp;

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
 * Non-BOF mode
 * ========================================================================= */
#else  /* !BOF */

#define internal_printf  printf
#define printoutput(x)   ((void)0)
#define bofstart()       (1)
#define bofstop()        ((void)0)

#endif /* BOF */

/* =========================================================================
 * Utf16ToUtf8
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

/*
 * =========================================================================
 * BOF entry-point template
 * =========================================================================
 * Every BOF's go() function should follow this pattern:
 *
 *   void go(char* args, int len) {
 *       if (!bofstart())          // allocates output buffer — MUST be first
 *           return;
 *
 *       datap parser;
 *       BeaconDataParse(&parser, args, len);
 *
 *       // ... do work, call internal_printf() or BeaconPrintf() ...
 *
 *       printoutput(TRUE);        // flush and free output buffer
 *       bofstop();                // release DynamicLoad libraries
 *   }
 *
 * The test BOF in this repo (test_bof.c) calls BeaconPrintf directly and
 * does not use internal_printf / printoutput, so it does not need bofstart()
 * for output — but it should still call it if it will call internal_printf,
 * and it must call bofstop() if DYNAMIC_LIB_COUNT is defined.
 * =========================================================================
 */