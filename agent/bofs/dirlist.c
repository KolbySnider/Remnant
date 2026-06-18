#include "base.h"


/* Build a "%llu B/KB/MB/GB" string without depending on MSVCRT$sprintf
 * (which pulls in __mingw_vsprintf — not exported by any DLL). */
static void format_size(unsigned long long sz, char* out, int outsz) {
    const char* unit;
    unsigned long long v;
    if      (sz < 1024ULL)               { v = sz;                 unit = "B";  }
    else if (sz < 1024ULL*1024)          { v = sz / 1024ULL;       unit = "KB"; }
    else if (sz < 1024ULL*1024*1024)     { v = sz / (1024ULL*1024);unit = "MB"; }
    else                                  { v = sz / (1024ULL*1024*1024); unit = "GB"; }
    /* Tiny manual itoa — avoids snprintf */
    char digits[32]; int n = 0;
    if (v == 0) digits[n++] = '0';
    while (v > 0) { digits[n++] = (char)('0' + (v % 10)); v /= 10; }
    int p = 0;
    while (n > 0 && p < outsz - 4) out[p++] = digits[--n];
    out[p++] = ' ';
    while (*unit && p < outsz - 1) out[p++] = *unit++;
    out[p] = '\0';
}

void go(char* args, int len) {
    if (!bofstart()) return;

    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    char searchPath[MAX_PATH];
    const char* directory = ".";

    if (len > 0 && args && args[0]) {
        datap parser;
        BeaconDataParse(&parser, args, len);
        int size = 0;
        char* path = BeaconDataExtract(&parser, &size);
        if (path && size > 0) directory = path;
    }

    /* Build "<dir>\*" without sprintf */
    int dlen = 0;
    while (directory[dlen] && dlen < MAX_PATH - 3) {
        searchPath[dlen] = directory[dlen];
        dlen++;
    }
    searchPath[dlen++] = '\\';
    searchPath[dlen++] = '*';
    searchPath[dlen]   = '\0';

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== DIRECTORY LISTING: %s ===\n\n", directory);
    BeaconPrintf(CALLBACK_OUTPUT, "%-40s %12s %s\n", "Name", "Size", "Type");
    BeaconPrintf(CALLBACK_OUTPUT, "%-40s %12s %s\n", "----", "----", "----");

    hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] FindFirstFile failed (err %lu)\n",
                     KERNEL32$GetLastError());
        printoutput(TRUE);
        bofstop();
        return;
    }

    int count = 0;
    do {
        if (MSVCRT$strcmp(findData.cFileName, ".") == 0 ||
            MSVCRT$strcmp(findData.cFileName, "..") == 0)
            continue;

        const char* type = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                           ? "<DIR>" : "";
        char attr[8] = {0};
        int  a = 0;
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)   attr[a++] = 'H';
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)   attr[a++] = 'S';
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_READONLY) attr[a++] = 'R';
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)  attr[a++] = 'A';
        attr[a] = '\0';

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            BeaconPrintf(CALLBACK_OUTPUT, "%-40s %12s %s %s\n",
                         findData.cFileName, "", type, attr);
        } else {
            ULARGE_INTEGER fileSize;
            fileSize.LowPart  = findData.nFileSizeLow;
            fileSize.HighPart = findData.nFileSizeHigh;
            char sizeStr[32];
            format_size(fileSize.QuadPart, sizeStr, sizeof(sizeStr));
            BeaconPrintf(CALLBACK_OUTPUT, "%-40s %12s %s %s\n",
                         findData.cFileName, sizeStr, type, attr);
        }
        count++;
    } while (KERNEL32$FindNextFileA(hFind, &findData));

    KERNEL32$FindClose(hFind);
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal items: %d\n", count);
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== END ===\n");
    printoutput(TRUE);
    bofstop();
}