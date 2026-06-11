
#include "base.c"

void go(char* args, int len) {
    /*
     * bofstart() MUST be the first call in go().
     * It allocates the output buffer that internal_printf / printoutput use.
     * Without it, any call to internal_printf will hit a NULL output pointer
     * and either silently do nothing (with the guard added to base.c) or
     * crash (original base.c).
     *
     * BeaconPrintf / BeaconOutput bypass the output buffer entirely and go
     * straight to the loader's encrypted accumulation buffer, so they do
     * not strictly need bofstart() — but calling it is still correct and
     * harmless, and required if you ever add internal_printf calls.
     */
    if (!bofstart())
        return;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Test BOF executed successfully!\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Args pointer: %p, length: %d\n",
                 (void*)args, len);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Test complete!\n");

    /*
     * printoutput(TRUE) flushes the internal_printf buffer and frees it.
     * Call it even if you only used BeaconPrintf — it is a no-op when
     * currentoutsize == 0 and it correctly NULLs the output pointer.
     */
    printoutput(TRUE);

    /* Release any libraries loaded via DynamicLoad */
    bofstop();
}