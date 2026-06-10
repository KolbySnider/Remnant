#define BOF
#include "beacon_compatibility.h"
#include "base.c"
#include <iphlpapi.h>

// Manual ntohs since WS2_32$ntohs is not declared
#define NTOHS(x)  ((((x) & 0xFF) << 8) | (((x) >> 8) & 0xFF))

#ifdef BOF

void go(char *args, unsigned long alen) {
    if (!bofstart()) {
        return;
    }

    PMIB_TCPTABLE pTcpTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    HANDLE hHeap = KERNEL32$GetProcessHeap();

    internal_printf("\n=== ACTIVE TCP CONNECTIONS ===\n\n");

    // First call to get required buffer size
    if (IPHLPAPI$GetTcpTable(NULL, &dwSize, TRUE) != ERROR_INSUFFICIENT_BUFFER) {
        internal_printf("Failed to get TCP table size (error: %lu)\n", KERNEL32$GetLastError());
        printoutput(TRUE);
        return;
    }

    pTcpTable = (PMIB_TCPTABLE)intAlloc(dwSize);
    if (pTcpTable == NULL) {
        internal_printf("Memory allocation failed\n");
        printoutput(TRUE);
        return;
    }

    if ((dwRetVal = IPHLPAPI$GetTcpTable(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {
        internal_printf("%-22s %-22s %-12s\n", "Local Address", "Remote Address", "State");
        internal_printf("-----------------------------------------------------------\n");

        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            MIB_TCPROW row = pTcpTable->table[i];

            struct in_addr localAddr;
            struct in_addr remoteAddr;
            localAddr.s_addr = row.dwLocalAddr;
            remoteAddr.s_addr = row.dwRemoteAddr;

            // Ports are in network byte order, convert to host
            u_short localPort = NTOHS((u_short)row.dwLocalPort);
            u_short remotePort = NTOHS((u_short)row.dwRemotePort);

            const char *stateStr = "UNKNOWN";
            switch (row.dwState) {
                case MIB_TCP_STATE_CLOSED:      stateStr = "CLOSED"; break;
                case MIB_TCP_STATE_LISTEN:      stateStr = "LISTEN"; break;
                case MIB_TCP_STATE_SYN_SENT:    stateStr = "SYN_SENT"; break;
                case MIB_TCP_STATE_SYN_RCVD:    stateStr = "SYN_RCVD"; break;
                case MIB_TCP_STATE_ESTAB:       stateStr = "ESTABLISHED"; break;
                case MIB_TCP_STATE_FIN_WAIT1:   stateStr = "FIN_WAIT1"; break;
                case MIB_TCP_STATE_FIN_WAIT2:   stateStr = "FIN_WAIT2"; break;
                case MIB_TCP_STATE_CLOSE_WAIT:  stateStr = "CLOSE_WAIT"; break;
                case MIB_TCP_STATE_CLOSING:     stateStr = "CLOSING"; break;
                case MIB_TCP_STATE_LAST_ACK:    stateStr = "LAST_ACK"; break;
                case MIB_TCP_STATE_TIME_WAIT:   stateStr = "TIME_WAIT"; break;
                case MIB_TCP_STATE_DELETE_TCB:  stateStr = "DELETE_TCB"; break;
            }

            internal_printf("%-15s:%-5d %-15s:%-5d %-12s\n",
                WS2_32$inet_ntoa(localAddr), localPort,
                WS2_32$inet_ntoa(remoteAddr), remotePort,
                stateStr);
        }
    } else {
        internal_printf("GetTcpTable failed with error: %lu\n", dwRetVal);
    }

    intFree(pTcpTable);
    internal_printf("\n=== END ===\n");
    printoutput(TRUE);
}

#else

int main() {
    char dummy[] = "";
    go(dummy, 0);
    return 0;
}

#endif