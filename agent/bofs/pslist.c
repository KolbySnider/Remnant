#include "base.h"
#include <tlhelp32.h>

void go(char* args, int len) {
    if (!bofstart()) return;

    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    int count = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "  %-8s %-8s %-7s %s\n",
                 "PID", "PPID", "THDS", "NAME");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-8s %-8s %-7s %s\n",
                 "---", "----", "----", "----");

    hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "  ERROR  snapshot failed (%lu)\n",
                     KERNEL32$GetLastError());
        printoutput(TRUE);
        bofstop();
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!KERNEL32$Process32First(hSnapshot, &pe32)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  ERROR  enumeration failed\n");
        KERNEL32$CloseHandle(hSnapshot);
        printoutput(TRUE);
        bofstop();
        return;
    }

    do {
        if (pe32.th32ProcessID == 0) continue;
        char name[33] = {0};
        for (int i = 0; i < 32 && pe32.szExeFile[i]; i++)
            name[i] = (char)pe32.szExeFile[i];
        BeaconPrintf(CALLBACK_OUTPUT, "  %-8lu %-8lu %-7lu %s\n",
                     pe32.th32ProcessID,
                     pe32.th32ParentProcessID,
                     pe32.cntThreads,
                     name);
        count++;
    } while (KERNEL32$Process32Next(hSnapshot, &pe32));

    KERNEL32$CloseHandle(hSnapshot);
    BeaconPrintf(CALLBACK_OUTPUT, "  ---\n  %d processes\n", count);
    printoutput(TRUE);
    bofstop();
}