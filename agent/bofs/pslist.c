#define BOF
#include "bofdefs.h"
#include "base.c"
#include <tlhelp32.h>

#ifdef BOF

// Flush threshold — keep each BeaconOutput call well under 4KB.
// At ~45 bytes/line this gives ~88 lines per flush, ~4KB per call.
// Even a machine with 500 processes will never hit the runner's buffer cap.
#define FLUSH_EVERY 90

void go(char *args, int len) {
    if (!bofstart()) {
        return;
    }

    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    int count = 0;

    // Print header then flush it immediately as its own chunk
    internal_printf("  %-8s %-8s %-7s %s\n", "PID", "PPID", "THDS", "NAME");
    internal_printf("  %-8s %-8s %-7s %s\n", "---", "----", "----", "----");
    printoutput(FALSE);

    hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        internal_printf("  ERROR  snapshot failed (%lu)\n", KERNEL32$GetLastError());
        printoutput(TRUE);
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!KERNEL32$Process32First(hSnapshot, &pe32)) {
        internal_printf("  ERROR  enumeration failed\n");
        KERNEL32$CloseHandle(hSnapshot);
        printoutput(TRUE);
        return;
    }

    do {
        if (pe32.th32ProcessID == 0) continue;

        // Truncate name - MAX_PATH is 260 but exe names realistically < 32 chars
        char name[33] = {0};
        int i;
        for (i = 0; i < 32 && pe32.szExeFile[i]; i++)
            name[i] = (char)pe32.szExeFile[i];

        // ~45 bytes per line
        internal_printf("  %-8lu %-8lu %-7lu %s\n",
            pe32.th32ProcessID,
            pe32.th32ParentProcessID,
            pe32.cntThreads,
            name);
        count++;

        // Flush every FLUSH_EVERY lines — keeps each BeaconOutput call ~4KB
        if (count % FLUSH_EVERY == 0) {
            printoutput(FALSE);
        }

    } while (KERNEL32$Process32Next(hSnapshot, &pe32));

    KERNEL32$CloseHandle(hSnapshot);

    internal_printf("  ---\n  %d processes\n", count);
    printoutput(TRUE);
}

#else

int main() {
    char dummy[] = "";
    go(dummy, 0);
    return 0;
}

#endif