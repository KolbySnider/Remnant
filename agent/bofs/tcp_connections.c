#include "base.c"
#include <iphlpapi.h>

#define NTOHS(x)  ((((x) & 0xFF) << 8) | (((x) >> 8) & 0xFF))

void go(char* args, int len) {
    if (!bofstart()) return;

    PMIB_TCPTABLE pTcpTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal;

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== ACTIVE TCP CONNECTIONS ===\n\n");

    if (IPHLPAPI$GetTcpTable(NULL, &dwSize, TRUE) != ERROR_INSUFFICIENT_BUFFER) {
        BeaconPrintf(CALLBACK_OUTPUT, "GetTcpTable sizing failed (err %lu)\n",
                     KERNEL32$GetLastError());
        printoutput(TRUE);
        bofstop();
        return;
    }

    pTcpTable = (PMIB_TCPTABLE)intAlloc(dwSize);
    if (!pTcpTable) {
        BeaconPrintf(CALLBACK_OUTPUT, "intAlloc failed\n");
        printoutput(TRUE);
        bofstop();
        return;
    }

    if ((dwRetVal = IPHLPAPI$GetTcpTable(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {
        BeaconPrintf(CALLBACK_OUTPUT, "%-22s %-22s %-12s\n",
                     "Local Address", "Remote Address", "State");
        BeaconPrintf(CALLBACK_OUTPUT,
                     "-----------------------------------------------------------\n");

        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            MIB_TCPROW row = pTcpTable->table[i];
            struct in_addr localAddr, remoteAddr;
            localAddr.s_addr  = row.dwLocalAddr;
            remoteAddr.s_addr = row.dwRemoteAddr;
            u_short localPort  = NTOHS((u_short)row.dwLocalPort);
            u_short remotePort = NTOHS((u_short)row.dwRemotePort);

            const char* st;
            switch (row.dwState) {
                case MIB_TCP_STATE_CLOSED:     st = "CLOSED";      break;
                case MIB_TCP_STATE_LISTEN:     st = "LISTEN";      break;
                case MIB_TCP_STATE_SYN_SENT:   st = "SYN_SENT";    break;
                case MIB_TCP_STATE_SYN_RCVD:   st = "SYN_RCVD";    break;
                case MIB_TCP_STATE_ESTAB:      st = "ESTABLISHED"; break;
                case MIB_TCP_STATE_FIN_WAIT1:  st = "FIN_WAIT1";   break;
                case MIB_TCP_STATE_FIN_WAIT2:  st = "FIN_WAIT2";   break;
                case MIB_TCP_STATE_CLOSE_WAIT: st = "CLOSE_WAIT";  break;
                case MIB_TCP_STATE_CLOSING:    st = "CLOSING";     break;
                case MIB_TCP_STATE_LAST_ACK:   st = "LAST_ACK";    break;
                case MIB_TCP_STATE_TIME_WAIT:  st = "TIME_WAIT";   break;
                case MIB_TCP_STATE_DELETE_TCB: st = "DELETE_TCB";  break;
                default:                       st = "UNKNOWN";     break;
            }
            BeaconPrintf(CALLBACK_OUTPUT, "%-15s:%-5d %-15s:%-5d %-12s\n",
                         WS2_32$inet_ntoa(localAddr),  localPort,
                         WS2_32$inet_ntoa(remoteAddr), remotePort,
                         st);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "GetTcpTable failed: %lu\n", dwRetVal);
    }

    intFree(pTcpTable);
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== END ===\n");
    printoutput(TRUE);
    bofstop();
}