#define BOF
#include "bofdefs.h"
#include "base.c"

#ifdef BOF

void go(char *args, int len) {
    if (!bofstart()) {
        return;
    }

    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    char searchPath[MAX_PATH];
    char *directory = ".";
    datap parser;

    if (len > 0) {
        BeaconDataParse(&parser, args, len);
        int size;
        char *path = BeaconDataExtract(&parser, &size);
        if (path && size > 0) {
            directory = path;
        }
    }

    MSVCRT$sprintf(searchPath, "%s\\*", directory);

    internal_printf("\n=== DIRECTORY LISTING: %s ===\n\n", directory);
    internal_printf("%-40s %12s %s\n", "Name", "Size", "Type");
    internal_printf("%-40s %12s %s\n", "----", "----", "----");

    hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        internal_printf("[!] Failed to open directory (Error: %d)\n", KERNEL32$GetLastError());
        printoutput(TRUE);
        return;
    }

    int count = 0;
    do {
        if (MSVCRT$strcmp(findData.cFileName, ".") == 0 || MSVCRT$strcmp(findData.cFileName, "..") == 0) {
            continue;
        }

        char *type = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "<DIR>" : "";
        char attributes[10] = {0};

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) MSVCRT$strcat(attributes, "H");
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) MSVCRT$strcat(attributes, "S");
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_READONLY) MSVCRT$strcat(attributes, "R");
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) MSVCRT$strcat(attributes, "A");

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            internal_printf("%-40s %12s %s %s\n",
                            findData.cFileName, "", type, attributes);
        } else {
            ULARGE_INTEGER fileSize;
            fileSize.LowPart = findData.nFileSizeLow;
            fileSize.HighPart = findData.nFileSizeHigh;

            char sizeStr[32];
            if (fileSize.QuadPart < 1024)
                MSVCRT$sprintf(sizeStr, "%llu B", fileSize.QuadPart);
            else if (fileSize.QuadPart < 1024*1024)
                MSVCRT$sprintf(sizeStr, "%llu KB", fileSize.QuadPart/1024);
            else if (fileSize.QuadPart < 1024*1024*1024)
                MSVCRT$sprintf(sizeStr, "%llu MB", fileSize.QuadPart/(1024*1024));
            else
                MSVCRT$sprintf(sizeStr, "%llu GB", fileSize.QuadPart/(1024*1024*1024));

            internal_printf("%-40s %12s %s %s\n",
                            findData.cFileName, sizeStr, type, attributes);
        }
        count++;
    } while (KERNEL32$FindNextFileA(hFind, &findData));

    KERNEL32$FindClose(hFind);
    internal_printf("\nTotal items: %d\n", count);
    internal_printf("\n=== END ===\n");
    printoutput(TRUE);
}

#else

int main(int argc, char **argv) {
    // Optional: pass directory as command line argument
    if (argc > 1) {
        go(argv[1], (int)strlen(argv[1]) + 1);
    } else {
        char dummy[] = "";
        go(dummy, 0);
    }
    return 0;
}

#endif