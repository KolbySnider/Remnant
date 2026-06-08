#define BOF
#include "base.c"
#include "beacon.h"
#include "bofdefs.h"
#include <windows.h>
#include <iphlpapi.h>


void go(char * args, unsigned long alen) {
    PMIB_IPNETTABLE pIpNetTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    HANDLE hHeap = KERNEL32$GetProcessHeap();

    IPHLPAPI$GetIpNetTable(NULL, &dwSize, 0);

    pIpNetTable = (PMIB_IPNETTABLE)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSize);

    if (pIpNetTable == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed\n");
        return;
    }

    // get table
    if ((dwRetVal = IPHLPAPI$GetIpNetTable(pIpNetTable, &dwSize, 0)) == NO_ERROR) {
        BeaconPrintf(CALLBACK_OUTPUT, "IP Address         MAC Address          Type\n");
        BeaconPrintf(CALLBACK_OUTPUT, "--------------------------------------------\n");

        for (int i = 0; i < (int)pIpNetTable->dwNumEntries; i++) {
            const char mac[18];
            MSVCRT$sprintf(mac, "%02X-%02X-%02X-%02X-%02X-%02X",
                 pIpNetTable->table[i].bPhysAddr[0], pIpNetTable->table[i].bPhysAddr[1],
                 pIpNetTable->table[i].bPhysAddr[2], pIpNetTable->table[i].bPhysAddr[3],
                 pIpNetTable->table[i].bPhysAddr[4], pIpNetTable->table[i].bPhysAddr[5]);

            struct in_addr addr;
            addr.s_addr = pIpNetTable->table[i].dwAddr;

            BeaconPrintf(CALLBACK_OUTPUT, "%-18s %-20s %lu\n",
                WS2_32$inet_ntoa(addr), mac, pIpNetTable->table[i].dwType);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "GetIpNetTable failed: %d\n", dwRetVal);
    }

    //  Free memory
    KERNEL32$HeapFree(hHeap, 0, pIpNetTable);
}