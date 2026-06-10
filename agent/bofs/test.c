#include "base.c"
#include "beacon_compatibility.h"
#include "beacon.h"


void go(char *args, int len) {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Test BOF executed successfully!\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Args pointer: %p, length: %d\n", args, len);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Test complete!\n");
}