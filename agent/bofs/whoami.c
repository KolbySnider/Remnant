#define BOF
#include "bofdefs.h"
#include "base.c"

#ifdef BOF

void go(char *args, int len) {
    if (!bofstart()) {
        return;
    }

    HANDLE hToken = NULL;
    TOKEN_USER *pTokenUser = NULL;
    TOKEN_ELEVATION_TYPE elevationType;
    DWORD dwSize = 0;
    char userName[256] = {0};
    char domainName[256] = {0};
    DWORD userSize = sizeof(userName);
    DWORD domainSize = sizeof(domainName);
    SID_NAME_USE sidType;
    char *stringSid = NULL;

    internal_printf("\n=== CURRENT USER INFORMATION ===\n\n");

    // Get current process token
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        internal_printf("[!] Failed to open process token: %d\n", KERNEL32$GetLastError());
        printoutput(TRUE);
        return;
    }

    // Get user SID
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    pTokenUser = (TOKEN_USER*)KERNEL32$LocalAlloc(LPTR, dwSize);

    if (pTokenUser && ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        if (ADVAPI32$LookupAccountSidA(NULL, pTokenUser->User.Sid, userName, &userSize,
                             domainName, &domainSize, &sidType)) {
            internal_printf("User: %s\\%s\n", domainName, userName);
        }

        if (ADVAPI32$ConvertSidToStringSidA(pTokenUser->User.Sid, &stringSid)) {
            internal_printf("SID: %s\n", stringSid);
            KERNEL32$LocalFree(stringSid);
        }
    }

    // Check if elevated
    dwSize = sizeof(TOKEN_ELEVATION_TYPE);
    if (ADVAPI32$GetTokenInformation(hToken, TokenElevationType, &elevationType, dwSize, &dwSize)) {
        internal_printf("Elevation Type: ");
        switch (elevationType) {
            case TokenElevationTypeDefault:
                internal_printf("Default (UAC not applicable)\n");
                break;
            case TokenElevationTypeFull:
                internal_printf("Full (Elevated)\n");
                break;
            case TokenElevationTypeLimited:
                internal_printf("Limited (Not Elevated)\n");
                break;
            default:
                internal_printf("Unknown\n");
        }
    }

    // Integrity level
    TOKEN_MANDATORY_LABEL *pTIL = NULL;
    dwSize = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    pTIL = (TOKEN_MANDATORY_LABEL*)KERNEL32$LocalAlloc(LPTR, dwSize);

    if (pTIL && ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwSize, &dwSize)) {
        PSID sid = pTIL->Label.Sid;
        BYTE *pSubAuthorityCount = (BYTE*)sid + 1;
        DWORD *pSubAuthority = (DWORD*)((BYTE*)sid + 8);
        DWORD integrityLevel = pSubAuthority[(*pSubAuthorityCount) - 1];

        internal_printf("Integrity Level: ");
        if (integrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
            internal_printf("System (0x%08X)\n", integrityLevel);
        else if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID)
            internal_printf("High (0x%08X)\n", integrityLevel);
        else if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID)
            internal_printf("Medium (0x%08X)\n", integrityLevel);
        else if (integrityLevel >= SECURITY_MANDATORY_LOW_RID)
            internal_printf("Low (0x%08X)\n", integrityLevel);
        else
            internal_printf("Unknown (0x%08X)\n", integrityLevel);

        KERNEL32$LocalFree(pTIL);
    }

    // Cleanup
    if (pTokenUser) KERNEL32$LocalFree(pTokenUser);
    if (hToken) KERNEL32$CloseHandle(hToken);

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