#include "base.h"


void go(char* args, int len) {
    if (!bofstart()) return;

    HANDLE hToken = NULL;
    TOKEN_USER* pTokenUser = NULL;
    TOKEN_ELEVATION_TYPE elevationType;
    DWORD dwSize = 0;
    char userName[256] = {0};
    char domainName[256] = {0};
    DWORD userSize = sizeof(userName);
    DWORD domainSize = sizeof(domainName);
    SID_NAME_USE sidType;
    char* stringSid = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== CURRENT USER INFORMATION ===\n\n");

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] OpenProcessToken failed: %lu\n",
                     KERNEL32$GetLastError());
        printoutput(TRUE);
        bofstop();
        return;
    }

    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    pTokenUser = (TOKEN_USER*)KERNEL32$LocalAlloc(LPTR, dwSize);
    if (pTokenUser && ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser,
                                                    dwSize, &dwSize)) {
        if (ADVAPI32$LookupAccountSidA(NULL, pTokenUser->User.Sid, userName, &userSize,
                                       domainName, &domainSize, &sidType)) {
            BeaconPrintf(CALLBACK_OUTPUT, "User: %s\\%s\n", domainName, userName);
        }
        if (ADVAPI32$ConvertSidToStringSidA(pTokenUser->User.Sid, &stringSid)) {
            BeaconPrintf(CALLBACK_OUTPUT, "SID: %s\n", stringSid);
            KERNEL32$LocalFree(stringSid);
        }
    }

    dwSize = sizeof(TOKEN_ELEVATION_TYPE);
    if (ADVAPI32$GetTokenInformation(hToken, TokenElevationType, &elevationType,
                                     dwSize, &dwSize)) {
        const char* etxt;
        switch (elevationType) {
            case TokenElevationTypeDefault: etxt = "Default (UAC not applicable)"; break;
            case TokenElevationTypeFull:    etxt = "Full (Elevated)";              break;
            case TokenElevationTypeLimited: etxt = "Limited (Not Elevated)";       break;
            default:                        etxt = "Unknown";                      break;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "Elevation Type: %s\n", etxt);
    }

    TOKEN_MANDATORY_LABEL* pTIL = NULL;
    dwSize = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    pTIL = (TOKEN_MANDATORY_LABEL*)KERNEL32$LocalAlloc(LPTR, dwSize);
    if (pTIL && ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, pTIL,
                                              dwSize, &dwSize)) {
        PSID sid = pTIL->Label.Sid;
        BYTE*  pSubAuthorityCount = (BYTE*)sid + 1;
        DWORD* pSubAuthority      = (DWORD*)((BYTE*)sid + 8);
        DWORD  integrityLevel     = pSubAuthority[(*pSubAuthorityCount) - 1];
        const char* itxt;
        if      (integrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) itxt = "System";
        else if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID)   itxt = "High";
        else if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID) itxt = "Medium";
        else if (integrityLevel >= SECURITY_MANDATORY_LOW_RID)    itxt = "Low";
        else                                                       itxt = "Unknown";
        BeaconPrintf(CALLBACK_OUTPUT, "Integrity Level: %s (0x%08lX)\n",
                     itxt, integrityLevel);
        KERNEL32$LocalFree(pTIL);
    }

    if (pTokenUser) KERNEL32$LocalFree(pTokenUser);
    if (hToken)     KERNEL32$CloseHandle(hToken);

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== END ===\n");
    printoutput(TRUE);
    bofstop();
}