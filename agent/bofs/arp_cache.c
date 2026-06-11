#include "base.c"
#include <iphlpapi.h>

/* Tiny byte-to-hex without sprintf (avoids __mingw_vsprintf). */
static void byte_hex(unsigned int b, char* out) {
    static const char H[] = "0123456789ABCDEF";
    out[0] = H[(b >> 4) & 0xF];
    out[1] = H[b & 0xF];
}

void go(char* args, int len) {
    if (!bofstart()) return;

    PMIB_IPNETTABLE pIpNetTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal;
    HANDLE hHeap = KERNEL32$GetProcessHeap();

    IPHLPAPI$GetIpNetTable(NULL, &dwSize, 0);

    pIpNetTable = (PMIB_IPNETTABLE)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSize);
    if (!pIpNetTable) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] HeapAlloc failed\n");
        printoutput(TRUE);
        bofstop();
        return;
    }

    if ((dwRetVal = IPHLPAPI$GetIpNetTable(pIpNetTable, &dwSize, 0)) == NO_ERROR) {
        BeaconPrintf(CALLBACK_OUTPUT, "IP Address         MAC Address          Type\n");
        BeaconPrintf(CALLBACK_OUTPUT, "--------------------------------------------\n");

        for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
            char mac[18];
            byte_hex(pIpNetTable->table[i].bPhysAddr[0], &mac[0]);  mac[2]  = '-';
            byte_hex(pIpNetTable->table[i].bPhysAddr[1], &mac[3]);  mac[5]  = '-';
            byte_hex(pIpNetTable->table[i].bPhysAddr[2], &mac[6]);  mac[8]  = '-';
            byte_hex(pIpNetTable->table[i].bPhysAddr[3], &mac[9]);  mac[11] = '-';
            byte_hex(pIpNetTable->table[i].bPhysAddr[4], &mac[12]); mac[14] = '-';
            byte_hex(pIpNetTable->table[i].bPhysAddr[5], &mac[15]); mac[17] = '\0';

            struct in_addr addr;
            addr.s_addr = pIpNetTable->table[i].dwAddr;

            BeaconPrintf(CALLBACK_OUTPUT, "%-18s %-20s %lu\n",
                         WS2_32$inet_ntoa(addr), mac,
                         pIpNetTable->table[i].dwType);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] GetIpNetTable failed: %lu\n", dwRetVal);
    }

    KERNEL32$HeapFree(hHeap, 0, pIpNetTable);
    printoutput(TRUE);
    bofstop();
}