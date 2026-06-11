#include "base.c"

void go(char* args, int len) {
    if (!bofstart()) return;

    WCHAR wComputer[256];
    char  computer[256];
    char  username[256];
    DWORD sizeW = 256;
    DWORD sizeA = sizeof(username);
    MEMORYSTATUSEX mem;

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== SYSTEM INFORMATION ===\n\n");

    if (KERNEL32$GetComputerNameExW(ComputerNameNetBIOS, wComputer, &sizeW)) {
        Kernel32$WideCharToMultiByte(CP_ACP, 0, wComputer, -1,
                                      computer, sizeof(computer), NULL, NULL);
        BeaconPrintf(CALLBACK_OUTPUT, "Computer Name: %s\n", computer);
    }

    if (SECUR32$GetUserNameExA(NameSamCompatible, username, &sizeA)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Username: %s\n", username);
    }

    mem.dwLength = sizeof(MEMORYSTATUSEX);
    if (KERNEL32$GlobalMemoryStatusEx(&mem)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Total RAM: %.2f GB\n",
                     (double)mem.ullTotalPhys / (1024.0 * 1024.0 * 1024.0));
        BeaconPrintf(CALLBACK_OUTPUT, "Available RAM: %.2f GB\n",
                     (double)mem.ullAvailPhys / (1024.0 * 1024.0 * 1024.0));
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== END ===\n");
    printoutput(TRUE);
    bofstop();
}