#pragma once
#ifndef BEACON_COMPATIBILITY_H_
#define BEACON_COMPATIBILITY_H_

/*
 * beacon_compatibility.h
 * ----------------------
 * Cobalt Strike 4.x Beacon API declarations used by BOFs.
 * When BOF == 1 the symbols are resolved by the loader at runtime
 * (DLL$Function naming convention).
 * When BOF is not defined the symbols map directly to the Win32 API so
 * the same source file can be unit-tested as a normal executable.
 */

#pragma intrinsic(memcmp, memcpy, strcpy, strcmp, _stricmp, strlen)

#define SECURITY_WIN32
#include <windows.h>
#include <process.h>
#include <winternl.h>
#include <imagehlp.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <windns.h>
#include <dbghelp.h>
#include <winldap.h>
#include <winnetwk.h>
#include <wtsapi32.h>
#include <shlwapi.h>
#include <ntsecapi.h>
#include <dsgetdc.h>
#include <security.h>
#include <aclapi.h>
#include <bcrypt.h>

/* =========================================================================
 * Beacon data-parser structures (same layout as CS beacon.h)
 * ========================================================================= */
typedef struct {
    char*  original;   /* original buffer start             */
    char*  buffer;     /* current read position             */
    int    length;     /* remaining readable bytes          */
    int    size;       /* total size (excluding 4-byte hdr) */
} datap;

typedef struct {
    char*  original;   /* heap buffer start   */
    char*  buffer;     /* current write pos   */
    int    length;     /* bytes written       */
    int    size;       /* total capacity      */
} formatp;

/* =========================================================================
 * BOF == 1: import everything through the loader's GOT
 * ========================================================================= */
#ifdef BOF

/* ---- KERNEL32 ---------------------------------------------------------- */
WINBASEAPI void*    WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI int      WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
WINBASEAPI void*    WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
WINBASEAPI LPVOID   WINAPI KERNEL32$HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);
WINBASEAPI HANDLE   WINAPI KERNEL32$GetProcessHeap(void);
WINBASEAPI BOOL     WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI DWORD    WINAPI KERNEL32$FormatMessageA(DWORD, LPCVOID, DWORD, DWORD, LPSTR, DWORD, va_list*);
WINBASEAPI int      WINAPI Kernel32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
WINBASEAPI BOOL     WINAPI KERNEL32$FileTimeToLocalFileTime(CONST FILETIME*, LPFILETIME);
WINBASEAPI BOOL     WINAPI KERNEL32$FileTimeToSystemTime(CONST FILETIME*, LPSYSTEMTIME);
WINBASEAPI BOOL     WINAPI KERNEL32$GetDateFormatW(LCID, DWORD, CONST SYSTEMTIME*, LPCWSTR, LPWSTR, int);
WINBASEAPI VOID     WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);
WINBASEAPI VOID     WINAPI KERNEL32$GetLocalTime(LPSYSTEMTIME);
WINBASEAPI WINBOOL  WINAPI KERNEL32$SystemTimeToFileTime(CONST SYSTEMTIME*, LPFILETIME);
WINBASEAPI WINBOOL  WINAPI KERNEL32$SystemTimeToTzSpecificLocalTime(CONST TIME_ZONE_INFORMATION*, CONST SYSTEMTIME*, LPSYSTEMTIME);
WINBASEAPI WINBOOL  WINAPI KERNEL32$GlobalMemoryStatusEx(LPMEMORYSTATUSEX);
WINBASEAPI WINBOOL  WINAPI KERNEL32$GetDiskFreeSpaceExA(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
WINBASEAPI HANDLE   WINAPI KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT DWORD KERNEL32$GetCurrentProcessId(VOID);
WINBASEAPI DWORD    WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI WINBOOL  WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI HANDLE   WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
WINBASEAPI DWORD    WINAPI KERNEL32$GetTickCount(VOID);
WINBASEAPI ULONGLONG WINAPI KERNEL32$GetTickCount64(VOID);
WINBASEAPI LPVOID   WINAPI KERNEL32$CreateFiber(SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
WINBASEAPI LPVOID   WINAPI KERNEL32$ConvertThreadToFiber(LPVOID);
WINBASEAPI WINBOOL  WINAPI KERNEL32$ConvertFiberToThread(VOID);
WINBASEAPI VOID     WINAPI KERNEL32$DeleteFiber(LPVOID);
WINBASEAPI VOID     WINAPI KERNEL32$SwitchToFiber(LPVOID);
WINBASEAPI DWORD    WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
WINBASEAPI VOID     WINAPI KERNEL32$Sleep(DWORD);
WINBASEAPI WINBOOL  WINAPI KERNEL32$DeleteFileW(LPCWSTR);
WINBASEAPI HANDLE   WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI HANDLE   WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI DWORD    WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
WINBASEAPI WINBOOL  WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
WINBASEAPI HANDLE   WINAPI KERNEL32$OpenProcess(DWORD, WINBOOL, DWORD);
WINBASEAPI WINBOOL  WINAPI KERNEL32$GetComputerNameExW(COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD);
WINBASEAPI int      WINAPI KERNEL32$lstrlenW(LPCWSTR);
WINBASEAPI LPWSTR   WINAPI KERNEL32$lstrcatW(LPWSTR, LPCWSTR);
WINBASEAPI LPWSTR   WINAPI KERNEL32$lstrcpynW(LPWSTR, LPCWSTR, int);
WINBASEAPI DWORD    WINAPI KERNEL32$GetFullPathNameW(LPCWSTR, DWORD, LPWSTR, LPWSTR*);
WINBASEAPI DWORD    WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
WINBASEAPI DWORD    WINAPI KERNEL32$GetCurrentDirectoryW(DWORD, LPWSTR);
WINBASEAPI HANDLE   WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
WINBASEAPI HANDLE   WINAPI KERNEL32$FindFirstFileA(char*, LPWIN32_FIND_DATA);
WINBASEAPI WINBOOL  WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
WINBASEAPI WINBOOL  WINAPI KERNEL32$FindNextFileA(HANDLE, LPWIN32_FIND_DATA);
WINBASEAPI WINBOOL  WINAPI KERNEL32$FindClose(HANDLE);
WINBASEAPI VOID     WINAPI KERNEL32$SetLastError(DWORD);
DECLSPEC_IMPORT HGLOBAL KERNEL32$GlobalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HGLOBAL KERNEL32$GlobalFree(HGLOBAL);
DECLSPEC_IMPORT LPTCH   WINAPI KERNEL32$GetEnvironmentStrings(void);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$FreeEnvironmentStringsA(LPSTR);
WINBASEAPI DWORD    WINAPI KERNEL32$ExpandEnvironmentStringsW(LPCWSTR, LPWSTR, DWORD);
WINBASEAPI HANDLE   WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
WINBASEAPI WINBOOL  WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
WINBASEAPI WINBOOL  WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
WINBASEAPI WINBOOL  WINAPI KERNEL32$Module32First(HANDLE, LPMODULEENTRY32);
WINBASEAPI WINBOOL  WINAPI KERNEL32$Module32Next(HANDLE, LPMODULEENTRY32);
WINBASEAPI HMODULE  WINAPI KERNEL32$LoadLibraryA(LPCSTR);
WINBASEAPI FARPROC  WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
WINBASEAPI WINBOOL  WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrlenA(LPCSTR);
WINBASEAPI BOOL     WINAPI KERNEL32$OpenProcessToken(HANDLE, DWORD, PHANDLE);

#define intAlloc(size)         KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size)  ((ptr) ? KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size) \
                                      : KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size))
#define intFree(addr)          KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
#define intZeroMemory(a, s)    MSVCRT$memset((a), 0, (s))

/* ---- MSVCRT ------------------------------------------------------------ */
WINBASEAPI void*  __cdecl MSVCRT$calloc(size_t, size_t);
WINBASEAPI void*  __cdecl MSVCRT$memcpy(void* __restrict__, const void* __restrict__, size_t);
WINBASEAPI int    __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
WINBASEAPI void*  __cdecl MSVCRT$realloc(void*, size_t);
WINBASEAPI void   __cdecl MSVCRT$free(void*);
WINBASEAPI void   __cdecl MSVCRT$memset(void*, int, size_t);
WINBASEAPI int    __cdecl MSVCRT$sprintf(char*, const char*, ...);
WINBASEAPI int    __cdecl MSVCRT$vsnprintf(char* __restrict__, size_t, const char* __restrict__, va_list);
WINBASEAPI int    __cdecl MSVCRT$_snwprintf(wchar_t* __restrict__, size_t, const wchar_t* __restrict__, ...);
WINBASEAPI errno_t __cdecl MSVCRT$wcsncpy_s(wchar_t*, rsize_t, const wchar_t*, rsize_t);
WINBASEAPI errno_t __cdecl MSVCRT$wcscpy_s(wchar_t*, rsize_t, const wchar_t*);
WINBASEAPI size_t  __cdecl MSVCRT$wcslen(const wchar_t*);
WINBASEAPI size_t  __cdecl MSVCRT$wcstombs(char* __restrict__, const wchar_t* __restrict__, size_t);
WINBASEAPI int     __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);
WINBASEAPI int     __cdecl MSVCRT$_wcsnicmp(const wchar_t*, const wchar_t*, size_t);
WINBASEAPI int     __cdecl MSVCRT$_strnicmp(const char*, const char*, size_t);
WINBASEAPI size_t  __cdecl MSVCRT$strnlen(const char*, size_t);
WINBASEAPI size_t  __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp(const char*, const char*);
WINBASEAPI int  __cdecl MSVCRT$strncmp(const char*, const char*, size_t);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char* __restrict__, const char* __restrict__);
DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strchr(const char*, int);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strtok(char* __restrict__, const char* __restrict__);
_CRTIMP char*   __cdecl MSVCRT$strtok_s(char*, const char*, char**);
WINBASEAPI unsigned long __cdecl MSVCRT$strtoul(const char* __restrict__, char** __restrict__, int);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcat(char* __restrict__, const char* __restrict__);
WINBASEAPI wchar_t* __cdecl MSVCRT$wcscat(wchar_t* __restrict__, const wchar_t* __restrict__);
WINBASEAPI wchar_t* __cdecl MSVCRT$wcscpy(wchar_t* __restrict__, const wchar_t* __restrict__);
WINBASEAPI _CONST_RETURN wchar_t* __cdecl MSVCRT$wcschr(const wchar_t*, wchar_t);
WINBASEAPI wchar_t* __cdecl MSVCRT$wcsrchr(const wchar_t*, wchar_t);
WINBASEAPI wchar_t* __cdecl MSVCRT$wcsstr(const wchar_t*, const wchar_t*);
WINBASEAPI unsigned long __cdecl MSVCRT$wcstoul(const wchar_t* __restrict__, wchar_t** __restrict__, int);
WINBASEAPI wchar_t* __cdecl MSVCRT$wcstok_s(wchar_t*, const wchar_t*, wchar_t**);
WINBASEAPI char*    __cdecl MSVCRT$_ultoa(unsigned long, char*, int);
WINBASEAPI struct tm* __cdecl MSVCRT$gmtime(const time_t*);
WINBASEAPI size_t    __cdecl MSVCRT$strftime(char*, size_t, const char*, const struct tm*);

/* ---- WTSAPI32 ---------------------------------------------------------- */
DECLSPEC_IMPORT DWORD WINAPI WTSAPI32$WTSEnumerateSessionsA(LPVOID, DWORD, DWORD, PWTS_SESSION_INFO*, DWORD*);
DECLSPEC_IMPORT DWORD WINAPI WTSAPI32$WTSQuerySessionInformationA(LPVOID, DWORD, WTS_INFO_CLASS, LPSTR*, DWORD*);
DECLSPEC_IMPORT DWORD WINAPI WTSAPI32$WTSFreeMemory(PVOID);

/* ---- IPHLPAPI ---------------------------------------------------------- */
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetAdaptersInfo(PIP_ADAPTER_INFO, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetIpForwardTable(PMIB_IPFORWARDTABLE, PULONG, WINBOOL);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetNetworkParams(PFIXED_INFO, PULONG);
DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetUdpTable(PMIB_UDPTABLE, PULONG, WINBOOL);
DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetTcpTable(PMIB_TCPTABLE, PULONG, WINBOOL);
DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetIpNetTable(PMIB_IPNETTABLE, PULONG, BOOL);

/* ---- DNSAPI ------------------------------------------------------------ */
DECLSPEC_IMPORT DNS_STATUS WINAPI DNSAPI$DnsQuery_A(PCSTR, WORD, DWORD, PIP4_ARRAY, PDNS_RECORD*, PVOID*);
DECLSPEC_IMPORT VOID       WINAPI DNSAPI$DnsFree(PVOID, DNS_FREE_TYPE);
DECLSPEC_IMPORT int        WINAPI DNSAPI$DnsGetCacheDataTable(PVOID);

/* ---- WSOCK32 / WS2_32 ------------------------------------------------- */
DECLSPEC_IMPORT unsigned long __stdcall WSOCK32$inet_addr(const char*);

typedef struct addrinfo {
    int             ai_flags;
    int             ai_family;
    int             ai_socktype;
    int             ai_protocol;
    size_t          ai_addrlen;
    char*           ai_canonname;
    struct sockaddr* ai_addr;
    struct addrinfo* ai_next;
} ADDRINFOA, *PADDRINFOA;

DECLSPEC_IMPORT int      __stdcall WS2_32$connect(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int      __stdcall WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT void     __stdcall WS2_32$freeaddrinfo(struct addrinfo*);
DECLSPEC_IMPORT int      __stdcall WS2_32$getaddrinfo(char*, char*, const struct addrinfo*, struct addrinfo**);
DECLSPEC_IMPORT u_long   __stdcall WS2_32$htonl(u_long);
DECLSPEC_IMPORT u_short  __stdcall WS2_32$htons(u_short);
DECLSPEC_IMPORT char*    __stdcall WS2_32$inet_ntoa(struct in_addr);
DECLSPEC_IMPORT int      __stdcall WS2_32$ioctlsocket(SOCKET, long, u_long*);
DECLSPEC_IMPORT int      __stdcall WS2_32$select(int, fd_set*, fd_set*, fd_set*, const struct timeval*);
DECLSPEC_IMPORT unsigned int __stdcall WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int      __stdcall WS2_32$__WSAFDIsSet(SOCKET, struct fd_set*);
DECLSPEC_IMPORT int      __stdcall WS2_32$WSAGetLastError(void);
DECLSPEC_IMPORT LPCWSTR  WINAPI    WS2_32$InetNtopW(INT, LPCVOID, LPWSTR, size_t);
DECLSPEC_IMPORT INT      WINAPI    WS2_32$inet_pton(INT, LPCSTR, PVOID);

/* ---- NETAPI32 ---------------------------------------------------------- */
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameA(LPVOID, LPVOID, LPVOID, LPVOID, ULONG, LPVOID);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetInfo(LPCWSTR, LPCWSTR, DWORD, LPBYTE*);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserModalsGet(LPCWSTR, DWORD, LPBYTE*);
WINBASEAPI DWORD WINAPI NETAPI32$NetServerEnum(LMCSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, DWORD, LMCSTR, LPDWORD);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetGroups(LPCWSTR, LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetLocalGroups(LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD);
WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);
WINBASEAPI DWORD WINAPI NETAPI32$NetGetAnyDCName(LPCWSTR, LPCWSTR, LPBYTE*);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserEnum(LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD);
WINBASEAPI DWORD WINAPI NETAPI32$NetGroupGetUsers(LPCWSTR, LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
WINBASEAPI DWORD WINAPI NETAPI32$NetQueryDisplayInformation(LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPDWORD, PVOID*);
WINBASEAPI DWORD WINAPI NETAPI32$NetLocalGroupEnum(LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
WINBASEAPI DWORD WINAPI NETAPI32$NetLocalGroupGetMembers(LPCWSTR, LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserSetInfo(LPCWSTR, LPCWSTR, DWORD, LPBYTE, LPDWORD);
WINBASEAPI DWORD WINAPI NETAPI32$NetShareEnum(LMSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD);
WINBASEAPI DWORD WINAPI NETAPI32$NetSessionEnum(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD);
WINBASEAPI DWORD WINAPI NETAPI32$NetWkstaUserEnum(LMSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD);
WINBASEAPI DWORD WINAPI NETAPI32$NetWkstaGetInfo(LMSTR, DWORD, LPBYTE*);
WINBASEAPI DWORD WINAPI NETAPI32$NetStatisticsGet(LMSTR, LMSTR, DWORD, DWORD, LPBYTE*);
WINBASEAPI DWORD WINAPI NETAPI32$NetRemoteTOD(LPCWSTR, LPBYTE*);

/* ---- MPR --------------------------------------------------------------- */
WINBASEAPI DWORD WINAPI MPR$WNetOpenEnumW(DWORD, DWORD, DWORD, LPNETRESOURCEW, LPHANDLE);
WINBASEAPI DWORD WINAPI MPR$WNetEnumResourceW(HANDLE, LPDWORD, LPVOID, LPDWORD);
WINBASEAPI DWORD WINAPI MPR$WNetCloseEnum(HANDLE);
WINBASEAPI DWORD WINAPI MPR$WNetGetConnectionW(LPCWSTR, LPWSTR, LPDWORD);
WINBASEAPI DWORD WINAPI MPR$WNetAddConnection2W(LPNETRESOURCEW, LPCWSTR, LPCWSTR, DWORD);
WINBASEAPI DWORD WINAPI MPR$WNetCancelConnection2W(LPCWSTR, DWORD, BOOL);

/* ---- USER32 ------------------------------------------------------------ */
WINUSERAPI int    WINAPI USER32$EnumDesktopWindows(HDESK, WNDENUMPROC, LPARAM);
WINUSERAPI int    WINAPI USER32$IsWindowVisible(HWND);
WINUSERAPI int    WINAPI USER32$GetWindowTextA(HWND, LPSTR, int);
WINUSERAPI int    WINAPI USER32$GetClassNameA(HWND, LPSTR, int);
WINUSERAPI HWND   WINAPI USER32$FindWindowExA(HWND, HWND, LPCSTR, LPCSTR);
WINUSERAPI LRESULT WINAPI USER32$SendMessageA(HWND, UINT, WPARAM, LPARAM);
WINUSERAPI BOOL   WINAPI USER32$EnumChildWindows(HWND, WNDENUMPROC, LPARAM);
WINBASEAPI WINBOOL WINAPI USER32$GetLastInputInfo(PLASTINPUTINFO);

/* ---- SECUR32 ----------------------------------------------------------- */
WINBASEAPI BOOLEAN WINAPI SECUR32$GetUserNameExA(int, LPSTR, PULONG);
WINBASEAPI NTSTATUS NTAPI SECUR32$LsaGetLogonSessionData(PLUID, PSECURITY_LOGON_SESSION_DATA*);
WINBASEAPI NTSTATUS NTAPI SECUR32$LsaFreeReturnBuffer(PVOID);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleW(SEC_WCHAR*, SEC_WCHAR*, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextW(PCredHandle, PCtxtHandle, SEC_WCHAR*, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(PCredHandle);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$DeleteSecurityContext(PCtxtHandle);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeContextBuffer(PVOID);

/* ---- SHLWAPI ----------------------------------------------------------- */
WINBASEAPI LPSTR WINAPI SHLWAPI$StrStrIA(LPCSTR, LPCSTR);

/* ---- ADVAPI32 ---------------------------------------------------------- */
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSidToStringSidW(PSID, LPWSTR*);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidW(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeNameA(LPCSTR, PLUID, LPSTR, LPDWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeDisplayNameA(LPCSTR, LPCSTR, LPSTR, LPDWORD, LPDWORD);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE, LPCSTR, DWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceStatus(SC_HANDLE, LPSERVICE_STATUS);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceConfigA(SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, LPDWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
WINADVAPI WINBOOL WINAPI ADVAPI32$EnumServicesStatusExA(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCSTR);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceStatusEx(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceConfig2A(SC_HANDLE, DWORD, LPBYTE, DWORD, LPDWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$ChangeServiceConfig2A(SC_HANDLE, DWORD, LPVOID);
WINADVAPI WINBOOL WINAPI ADVAPI32$ChangeServiceConfigA(SC_HANDLE, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$CreateServiceA(SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
WINADVAPI WINBOOL WINAPI ADVAPI32$DeleteService(SC_HANDLE);
WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
WINADVAPI LONG WINAPI ADVAPI32$RegCreateKeyA(HKEY, LPCSTR, PHKEY);
WINADVAPI LONG WINAPI ADVAPI32$RegCreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
WINADVAPI LONG WINAPI ADVAPI32$RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, CONST BYTE*, DWORD);
WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
WINADVAPI LONG WINAPI ADVAPI32$RegQueryInfoKeyA(HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
WINADVAPI LONG WINAPI ADVAPI32$RegEnumValueA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
WINADVAPI LONG WINAPI ADVAPI32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteValueA(HKEY, LPCSTR);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyExA(HKEY, LPCSTR, REGSAM, DWORD);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyValueA(HKEY, LPCSTR, LPCSTR);
WINADVAPI LONG WINAPI ADVAPI32$RegConnectRegistryA(LPCSTR, HKEY, PHKEY);
WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
WINADVAPI LONG WINAPI ADVAPI32$RegSaveKeyExA(HKEY, LPCSTR, LPSECURITY_ATTRIBUTES, DWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetFileSecurityW(LPCWSTR, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, DWORD, LPDWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR, PSID*, LPBOOL);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR, LPBOOL, PACL*, LPBOOL);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetAclInformation(PACL, LPVOID, DWORD, ACL_INFORMATION_CLASS);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetAce(PACL, DWORD, LPVOID*);
WINADVAPI VOID   WINAPI ADVAPI32$MapGenericMask(PDWORD, PGENERIC_MAPPING);
WINADVAPI WINBOOL WINAPI ADVAPI32$InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR, DWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR, WINBOOL, PACL, WINBOOL);
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorW(PSECURITY_DESCRIPTOR, DWORD, SECURITY_INFORMATION, LPWSTR*, PULONG);
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorW(LPCWSTR, DWORD, PSECURITY_DESCRIPTOR*, PULONG);
WINADVAPI WINBOOL WINAPI ADVAPI32$StartServiceA(SC_HANDLE, DWORD, LPCSTR*);
WINADVAPI WINBOOL WINAPI ADVAPI32$ControlService(SC_HANDLE, DWORD, LPSERVICE_STATUS);
WINADVAPI WINBOOL WINAPI ADVAPI32$EnumDependentServicesA(SC_HANDLE, DWORD, LPENUM_SERVICE_STATUSA, DWORD, LPDWORD, LPDWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$CryptAcquireContextA(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$CryptCreateHash(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
WINADVAPI WINBOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV, DWORD);
WINIMPM  WINBOOL WINAPI ADVAPI32$CryptHashData(HCRYPTHASH, CONST BYTE*, DWORD, DWORD);
WINIMPM  WINBOOL WINAPI ADVAPI32$CryptGetHashParam(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
WINIMPM  WINBOOL WINAPI ADVAPI32$CryptDestroyHash(HCRYPTHASH);
WINBASEAPI LONG WINAPI ADVAPI32$RegGetKeySecurity(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, LPDWORD);
WINBASEAPI LONG WINAPI ADVAPI32$RegSetKeySecurity(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
WINBASEAPI DWORD WINAPI ADVAPI32$SetEntriesInAclA(ULONG, PEXPLICIT_ACCESS_A, PACL, PACL*);

/* ---- NTDLL ------------------------------------------------------------- */
WINBASEAPI NTSTATUS NTAPI NTDLL$NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtClose(HANDLE);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtFsControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);

/* ---- IMAGEHLP ---------------------------------------------------------- */
WINBASEAPI WINBOOL IMAGEAPI IMAGEHLP$ImageEnumerateCertificates(HANDLE, WORD, PDWORD, PDWORD, DWORD);
WINBASEAPI WINBOOL IMAGEAPI IMAGEHLP$ImageGetCertificateHeader(HANDLE, DWORD, LPWIN_CERTIFICATE);
WINBASEAPI WINBOOL IMAGEAPI IMAGEHLP$ImageGetCertificateData(HANDLE, DWORD, LPWIN_CERTIFICATE, PDWORD);

/* ---- CRYPT32 ----------------------------------------------------------- */
WINIMPM WINBOOL WINAPI CRYPT32$CryptVerifyMessageSignature(PCRYPT_VERIFY_MESSAGE_PARA, DWORD, const BYTE*, DWORD, BYTE*, DWORD*, PCCERT_CONTEXT*);
WINIMPM DWORD   WINAPI CRYPT32$CertGetNameStringW(PCCERT_CONTEXT, DWORD, DWORD, void*, LPWSTR, DWORD);
WINIMPM PCCERT_CONTEXT WINAPI CRYPT32$CertCreateCertificateContext(DWORD, const BYTE*, DWORD);
WINIMPM WINBOOL WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT);
WINIMPM WINBOOL WINAPI CRYPT32$CertGetCertificateContextProperty(PCCERT_CONTEXT, DWORD, void*, DWORD*);
WINIMPM WINBOOL WINAPI CRYPT32$CertGetCertificateChain(HCERTCHAINENGINE, PCCERT_CONTEXT, LPFILETIME, HCERTSTORE, PCERT_CHAIN_PARA, DWORD, LPVOID, PCCERT_CHAIN_CONTEXT*);
WINIMPM VOID    WINAPI CRYPT32$CertFreeCertificateChain(PCCERT_CHAIN_CONTEXT);
WINIMPM PCCRYPT_OID_INFO WINAPI CRYPT32$CryptFindOIDInfo(DWORD, void*, DWORD);

/* ---- OLE32 / OLEAUT32 ------------------------------------------------- */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE*, void*, DWORD, DWORD, void*, DWORD, void*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CLSIDFromString(LPCOLESTR, LPCLSID);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString(LPCOLESTR, LPIID);
DECLSPEC_IMPORT int     WINAPI OLE32$StringFromGUID2(REFGUID, LPOLESTR, int);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);
DECLSPEC_IMPORT LPVOID  WINAPI OLE32$CoTaskMemAlloc(SIZE_T);
DECLSPEC_IMPORT void    WINAPI OLE32$CoTaskMemFree(LPVOID);
DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT INT     WINAPI OLEAUT32$SysReAllocString(BSTR*, const OLECHAR*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT UINT    WINAPI OLEAUT32$SysStringLen(BSTR);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantInit(VARIANTARG*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantClear(VARIANTARG*);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantChangeType(VARIANTARG*, VARIANTARG*, USHORT, VARTYPE);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayLock(SAFEARRAY*);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayGetLBound(SAFEARRAY*, UINT, LONG*);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayGetUBound(SAFEARRAY*, UINT, LONG*);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayGetElement(SAFEARRAY*, LONG*, void*);
DECLSPEC_IMPORT UINT    WINAPI OLEAUT32$SafeArrayGetElemsize(SAFEARRAY*);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayAccessData(SAFEARRAY*, void HUGEP**);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayUnaccessData(SAFEARRAY*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SafeArrayDestroy(SAFEARRAY*);

/* ---- BCRYPT ------------------------------------------------------------ */
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, DWORD);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptSetProperty(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, DWORD);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDestroyKey(BCRYPT_KEY_HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDecrypt(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCreateHash(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, DWORD);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDestroyHash(BCRYPT_HASH_HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptHashData(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptFinishHash(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);

/* ---- DBGHELP ----------------------------------------------------------- */
DECLSPEC_IMPORT WINBOOL WINAPI DBGHELP$MiniDumpWriteDump(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, CONST PMINIDUMP_EXCEPTION_INFORMATION, CONST PMINIDUMP_USER_STREAM_INFORMATION, CONST PMINIDUMP_CALLBACK_INFORMATION);

/* ---- WLDAP32 ----------------------------------------------------------- */
WINLDAPAPI LDAP*  LDAPAPI WLDAP32$ldap_init(PSTR, ULONG);
WINLDAPAPI ULONG  LDAPAPI WLDAP32$ldap_bind_s(LDAP*, const PSTR, const PCHAR, ULONG);
WINLDAPAPI ULONG  LDAPAPI WLDAP32$ldap_search_s(LDAP*, PSTR, ULONG, PSTR, PZPSTR, ULONG, PLDAPMessage*);
WINLDAPAPI ULONG  LDAPAPI WLDAP32$ldap_count_entries(LDAP*, LDAPMessage*);
WINLDAPAPI struct berval** LDAPAPI WLDAP32$ldap_get_values_lenA(LDAP*, LDAPMessage*, const PCHAR);
WINLDAPAPI ULONG  LDAPAPI WLDAP32$ldap_value_free_len(struct berval**);
WINLDAPAPI ULONG  LDAPAPI WLDAP32$ldap_set_optionA(LDAP*, int, const void*);
WINLDAPAPI PLDAPSearch LDAPAPI WLDAP32$ldap_search_init_pageA(PLDAP, const PCHAR, ULONG, const PCHAR, PCHAR[], ULONG, PLDAPControlA*, PLDAPControlA*, ULONG, ULONG, PLDAPSortKeyA*);
WINLDAPAPI ULONG  LDAPAPI WLDAP32$ldap_get_paged_count(PLDAP, PLDAPSearch, ULONG*, PLDAPMessage);
WINLDAPAPI ULONG  LDAPAPI WLDAP32$ldap_get_next_page_s(PLDAP, PLDAPSearch, struct l_timeval*, ULONG, ULONG*, LDAPMessage**);
WINLDAPAPI LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
WINLDAPAPI LDAPMessage* LDAPAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
WINLDAPAPI PCHAR  LDAPAPI WLDAP32$ldap_first_attribute(LDAP*, LDAPMessage*, BerElement**);
WINLDAPAPI ULONG  LDAPAPI WLDAP32$ldap_count_values(PCHAR);
WINLDAPAPI PCHAR* LDAPAPI WLDAP32$ldap_get_values(LDAP*, LDAPMessage*, const PSTR);
WINLDAPAPI ULONG  LDAPAPI WLDAP32$ldap_value_free(PCHAR*);
WINLDAPAPI PCHAR  LDAPAPI WLDAP32$ldap_next_attribute(LDAP*, LDAPMessage*, BerElement*);
WINLDAPAPI VOID   LDAPAPI WLDAP32$ber_free(BerElement*, INT);
WINLDAPAPI VOID   LDAPAPI WLDAP32$ber_bvfree(struct berval*);
WINLDAPAPI VOID   LDAPAPI WLDAP32$ldap_memfree(PCHAR);
WINLDAPAPI ULONG  LDAPAPI WLDAP32$ldap_unbind(LDAP*);
WINLDAPAPI ULONG  LDAPAPI WLDAP32$ldap_unbind_s(LDAP*);
WINLDAPAPI ULONG  LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT LDAP* LDAPAPI WLDAP32$ldap_initW(const PWSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_connect(LDAP*, LDAP_TIMEVAL*);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_set_optionW(LDAP*, int, const void*);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_get_optionW(LDAP*, int, void*);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_sasl_bind_sW(LDAP*, const PWCHAR, const PWCHAR, const BERVAL*, PLDAPControlW*, PLDAPControlW*, PBERVAL*);

/* ---- RPCRT4 ------------------------------------------------------------ */
RPCRTAPI RPC_STATUS RPC_ENTRY RPCRT4$UuidToStringA(UUID*, RPC_CSTR*);
RPCRTAPI RPC_STATUS RPC_ENTRY RPCRT4$RpcStringFreeA(RPC_CSTR*);

/* ---- PSAPI ------------------------------------------------------------- */
DECLSPEC_IMPORT WINBOOL WINAPI PSAPI$EnumProcessModulesEx(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
DECLSPEC_IMPORT DWORD   WINAPI PSAPI$GetModuleFileNameExA(HANDLE, HMODULE, LPSTR, DWORD);

/* ---- VERSION ----------------------------------------------------------- */
DECLSPEC_IMPORT DWORD   WINAPI VERSION$GetFileVersionInfoSizeA(LPCSTR, LPDWORD);
DECLSPEC_IMPORT WINBOOL WINAPI VERSION$GetFileVersionInfoA(LPCSTR, DWORD, DWORD, LPVOID);
DECLSPEC_IMPORT WINBOOL WINAPI VERSION$VerQueryValueA(LPCVOID, LPCSTR, LPVOID*, PUINT);

/* =========================================================================
 * BOF == 1: redirect standard names to the BOF import table
 * ========================================================================= */

#else /* !BOF – build as normal Windows executable for unit-testing */

#define intAlloc(size)         HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size)  ((ptr) ? HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size) \
                                      : HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size))
#define intFree(addr)          HeapFree(GetProcessHeap(), 0, addr)
#define intZeroMemory(a, s)    memset((a), 0, (s))

#define KERNEL32$VirtualAlloc               VirtualAlloc
#define KERNEL32$VirtualFree                VirtualFree
#define KERNEL32$LocalAlloc                 LocalAlloc
#define KERNEL32$LocalFree                  LocalFree
#define KERNEL32$HeapAlloc                  HeapAlloc
#define KERNEL32$HeapReAlloc                HeapReAlloc
#define KERNEL32$GetProcessHeap             GetProcessHeap
#define KERNEL32$HeapFree                   HeapFree
#define Kernel32$FormatMessageA             FormatMessageA
#define Kernel32$WideCharToMultiByte        WideCharToMultiByte
#define KERNEL32$FileTimeToLocalFileTime    FileTimeToLocalFileTime
#define KERNEL32$FileTimeToSystemTime       FileTimeToSystemTime
#define KERNEL32$GetDateFormatW             GetDateFormatW
#define KERNEL32$GetSystemTimeAsFileTime    GetSystemTimeAsFileTime
#define KERNEL32$GetLocalTime               GetLocalTime
#define KERNEL32$SystemTimeToFileTime       SystemTimeToFileTime
#define KERNEL32$SystemTimeToTzSpecificLocalTime SystemTimeToTzSpecificLocalTime
#define KERNEL32$GlobalMemoryStatusEx       GlobalMemoryStatusEx
#define KERNEL32$GetDiskFreeSpaceExA        GetDiskFreeSpaceExA
#define KERNEL32$GetCurrentProcess          GetCurrentProcess
#define KERNEL32$GetCurrentProcessId        GetCurrentProcessId
#define KERNEL32$GetLastError               GetLastError
#define KERNEL32$CloseHandle                CloseHandle
#define KERNEL32$CreateThread               CreateThread
#define KERNEL32$GetTickCount               GetTickCount
#define KERNEL32$GetTickCount64             GetTickCount64
#define KERNEL32$CreateFiber                CreateFiber
#define KERNEL32$ConvertThreadToFiber       ConvertThreadToFiber
#define KERNEL32$ConvertFiberToThread       ConvertFiberToThread
#define KERNEL32$DeleteFiber                DeleteFiber
#define KERNEL32$SwitchToFiber              SwitchToFiber
#define KERNEL32$WaitForSingleObject        WaitForSingleObject
#define KERNEL32$Sleep                      Sleep
#define KERNEL32$DeleteFileW                DeleteFileW
#define KERNEL32$CreateFileW                CreateFileW
#define KERNEL32$CreateFileA                CreateFileA
#define KERNEL32$GetFileSize                GetFileSize
#define KERNEL32$ReadFile                   ReadFile
#define KERNEL32$OpenProcess                OpenProcess
#define KERNEL32$GetComputerNameExW         GetComputerNameExW
#define KERNEL32$lstrlenW                   lstrlenW
#define KERNEL32$lstrcatW                   lstrcatW
#define KERNEL32$lstrcpynW                  lstrcpynW
#define KERNEL32$GetFullPathNameW           GetFullPathNameW
#define KERNEL32$GetFileAttributesW         GetFileAttributesW
#define KERNEL32$GetCurrentDirectoryW       GetCurrentDirectoryW
#define KERNEL32$FindFirstFileW             FindFirstFileW
#define KERNEL32$FindNextFileW              FindNextFileW
#define KERNEL32$FindFirstFileA             FindFirstFileA
#define KERNEL32$FindNextFileA              FindNextFileA
#define KERNEL32$FindClose                  FindClose
#define KERNEL32$SetLastError               SetLastError
#define KERNEL32$GlobalAlloc                GlobalAlloc
#define KERNEL32$GlobalFree                 GlobalFree
#define KERNEL32$GetEnvironmentStrings      GetEnvironmentStrings
#define KERNEL32$FreeEnvironmentStringsA    FreeEnvironmentStringsA
#define KERNEL32$ExpandEnvironmentStringsW  ExpandEnvironmentStringsW
#define KERNEL32$CreateToolhelp32Snapshot   CreateToolhelp32Snapshot
#define KERNEL32$Process32First             Process32First
#define KERNEL32$Process32Next              Process32Next
#define KERNEL32$Module32First              Module32First
#define KERNEL32$Module32Next               Module32Next
#define KERNEL32$LoadLibraryA               LoadLibraryA
#define KERNEL32$GetProcAddress             GetProcAddress
#define KERNEL32$FreeLibrary                FreeLibrary
#define KERNEL32$lstrlenA                   lstrlenA
#define KERNEL32$OpenProcessToken           OpenProcessToken
#define MSVCRT$calloc                       calloc
#define MSVCRT$memcpy                       memcpy
#define MSVCRT$memcmp                       memcmp
#define MSVCRT$realloc                      realloc
#define MSVCRT$free                         free
#define MSVCRT$memset                       memset
#define MSVCRT$sprintf                      sprintf
#define MSVCRT$vsnprintf                    vsnprintf
#define MSVCRT$_snwprintf                   _snwprintf
#define MSVCRT$wcsncpy_s                    wcsncpy_s
#define MSVCRT$wcscpy_s                     wcscpy_s
#define MSVCRT$wcslen                       wcslen
#define MSVCRT$wcstombs                     wcstombs
#define MSVCRT$_wcsicmp                     _wcsicmp
#define MSVCRT$_wcsnicmp                    _wcsnicmp
#define MSVCRT$_strnicmp                    _strnicmp
#define MSVCRT$strnlen                      strnlen
#define MSVCRT$strlen                       strlen
#define MSVCRT$strcmp                       strcmp
#define MSVCRT$strncmp                      strncmp
#define MSVCRT$_stricmp                     _stricmp
#define MSVCRT$strcpy                       strcpy
#define MSVCRT$strstr                       strstr
#define MSVCRT$strchr                       strchr
#define MSVCRT$strtok                       strtok
#define MSVCRT$strtok_s                     strtok_s
#define MSVCRT$strtoul                      strtoul
#define MSVCRT$strcat                       strcat
#define MSVCRT$_ultoa                       _ultoa
#define MSVCRT$wcscat                       wcscat
#define MSVCRT$wcscpy                       wcscpy
#define MSVCRT$wcschr                       wcschr
#define MSVCRT$wcsrchr                      wcsrchr
#define MSVCRT$wcsstr                       wcsstr
#define MSVCRT$wcstoul                      wcstoul
#define MSVCRT$wcstok_s                     wcstok_s
#define MSVCRT$gmtime                       gmtime
#define MSVCRT$strftime                     strftime
#define WTSAPI32$WTSEnumerateSessionsA      WTSEnumerateSessionsA
#define WTSAPI32$WTSQuerySessionInformationA WTSQuerySessionInformationA
#define WTSAPI32$WTSFreeMemory              WTSFreeMemory
#define IPHLPAPI$GetAdaptersInfo            GetAdaptersInfo
#define IPHLPAPI$GetIpForwardTable          GetIpForwardTable
#define IPHLPAPI$GetNetworkParams           GetNetworkParams
#define IPHLPAPI$GetUdpTable                GetUdpTable
#define IPHLPAPI$GetTcpTable                GetTcpTable
#define IPHLPAPI$GetIpNetTable              GetIpNetTable
#define DNSAPI$DnsQuery_A                   DnsQuery_A
#define DNSAPI$DnsFree                      DnsFree
#define DNSAPI$DnsGetCacheDataTable         DnsGetCacheDataTable
#define WSOCK32$inet_addr                   inet_addr
#define WS2_32$connect                      connect
#define WS2_32$closesocket                  closesocket
#define WS2_32$freeaddrinfo                 freeaddrinfo
#define WS2_32$getaddrinfo                  getaddrinfo
#define WS2_32$htonl                        htonl
#define WS2_32$htons                        htons
#define WS2_32$inet_ntoa                    inet_ntoa
#define WS2_32$ioctlsocket                  ioctlsocket
#define WS2_32$select                       select
#define WS2_32$socket                       socket
#define WS2_32$__WSAFDIsSet                 __WSAFDIsSet
#define WS2_32$WSAGetLastError              WSAGetLastError
#define WS2_32$InetNtopW                    InetNtopW
#define WS2_32$inet_pton                    inet_pton
#define NETAPI32$DsGetDcNameA               DsGetDcNameA
#define NETAPI32$NetUserGetInfo             NetUserGetInfo
#define NETAPI32$NetUserModalsGet           NetUserModalsGet
#define NETAPI32$NetServerEnum              NetServerEnum
#define NETAPI32$NetUserGetGroups           NetUserGetGroups
#define NETAPI32$NetUserGetLocalGroups      NetUserGetLocalGroups
#define NETAPI32$NetApiBufferFree           NetApiBufferFree
#define NETAPI32$NetGetAnyDCName            NetGetAnyDCName
#define NETAPI32$NetUserEnum                NetUserEnum
#define NETAPI32$NetGroupGetUsers           NetGroupGetUsers
#define NETAPI32$NetQueryDisplayInformation NetQueryDisplayInformation
#define NETAPI32$NetLocalGroupEnum          NetLocalGroupEnum
#define NETAPI32$NetLocalGroupGetMembers    NetLocalGroupGetMembers
#define NETAPI32$NetUserSetInfo             NetUserSetInfo
#define NETAPI32$NetShareEnum               NetShareEnum
#define NETAPI32$NetSessionEnum             NetSessionEnum
#define NETAPI32$NetWkstaUserEnum           NetWkstaUserEnum
#define NETAPI32$NetWkstaGetInfo            NetWkstaGetInfo
#define NETAPI32$NetStatisticsGet           NetStatisticsGet
#define NETAPI32$NetRemoteTOD               NetRemoteTOD
#define MPR$WNetOpenEnumW                   WNetOpenEnumW
#define MPR$WNetEnumResourceW               WNetEnumResourceW
#define MPR$WNetCloseEnum                   WNetCloseEnum
#define MPR$WNetGetConnectionW              WNetGetConnectionW
#define MPR$WNetAddConnection2W             WNetAddConnection2W
#define MPR$WNetCancelConnection2W          WNetCancelConnection2W
#define USER32$EnumDesktopWindows           EnumDesktopWindows
#define USER32$IsWindowVisible              IsWindowVisible
#define USER32$GetWindowTextA               GetWindowTextA
#define USER32$GetClassNameA                GetClassNameA
#define USER32$FindWindowExA                FindWindowExA
#define USER32$SendMessageA                 SendMessageA
#define USER32$EnumChildWindows             EnumChildWindows
#define USER32$GetLastInputInfo             GetLastInputInfo
#define SECUR32$GetUserNameExA              GetUserNameExA
#define SECUR32$LsaGetLogonSessionData      LsaGetLogonSessionData
#define SECUR32$LsaFreeReturnBuffer         LsaFreeReturnBuffer
#define SECUR32$AcquireCredentialsHandleW   AcquireCredentialsHandleW
#define SECUR32$InitializeSecurityContextW  InitializeSecurityContextW
#define SECUR32$FreeCredentialsHandle       FreeCredentialsHandle
#define SECUR32$DeleteSecurityContext       DeleteSecurityContext
#define SECUR32$FreeContextBuffer           FreeContextBuffer
#define SHLWAPI$StrStrIA                    StrStrIA
#define ADVAPI32$OpenProcessToken           OpenProcessToken
#define ADVAPI32$GetTokenInformation        GetTokenInformation
#define ADVAPI32$ConvertSidToStringSidA     ConvertSidToStringSidA
#define ADVAPI32$ConvertSidToStringSidW     ConvertSidToStringSidW
#define ADVAPI32$LookupAccountSidA          LookupAccountSidA
#define ADVAPI32$LookupAccountSidW          LookupAccountSidW
#define ADVAPI32$LookupPrivilegeNameA       LookupPrivilegeNameA
#define ADVAPI32$LookupPrivilegeDisplayNameA LookupPrivilegeDisplayNameA
#define ADVAPI32$OpenSCManagerA             OpenSCManagerA
#define ADVAPI32$OpenServiceA               OpenServiceA
#define ADVAPI32$QueryServiceStatus         QueryServiceStatus
#define ADVAPI32$QueryServiceConfigA        QueryServiceConfigA
#define ADVAPI32$CloseServiceHandle         CloseServiceHandle
#define ADVAPI32$EnumServicesStatusExA      EnumServicesStatusExA
#define ADVAPI32$QueryServiceStatusEx       QueryServiceStatusEx
#define ADVAPI32$QueryServiceConfig2A       QueryServiceConfig2A
#define ADVAPI32$ChangeServiceConfig2A      ChangeServiceConfig2A
#define ADVAPI32$ChangeServiceConfigA       ChangeServiceConfigA
#define ADVAPI32$CreateServiceA             CreateServiceA
#define ADVAPI32$DeleteService              DeleteService
#define ADVAPI32$RegOpenKeyExA              RegOpenKeyExA
#define ADVAPI32$RegOpenKeyExW              RegOpenKeyExW
#define ADVAPI32$RegCreateKeyA              RegCreateKeyA
#define ADVAPI32$RegCreateKeyExA            RegCreateKeyExA
#define ADVAPI32$RegSetValueExA             RegSetValueExA
#define ADVAPI32$RegQueryValueExA           RegQueryValueExA
#define ADVAPI32$RegQueryValueExW           RegQueryValueExW
#define ADVAPI32$RegQueryInfoKeyA           RegQueryInfoKeyA
#define ADVAPI32$RegEnumValueA              RegEnumValueA
#define ADVAPI32$RegEnumKeyExA              RegEnumKeyExA
#define ADVAPI32$RegDeleteValueA            RegDeleteValueA
#define ADVAPI32$RegDeleteKeyExA            RegDeleteKeyExA
#define ADVAPI32$RegDeleteKeyValueA         RegDeleteKeyValueA
#define ADVAPI32$RegConnectRegistryA        RegConnectRegistryA
#define ADVAPI32$RegCloseKey                RegCloseKey
#define ADVAPI32$RegSaveKeyExA              RegSaveKeyExA
#define ADVAPI32$GetFileSecurityW           GetFileSecurityW
#define ADVAPI32$GetSecurityDescriptorOwner GetSecurityDescriptorOwner
#define ADVAPI32$GetSecurityDescriptorDacl  GetSecurityDescriptorDacl
#define ADVAPI32$GetAclInformation          GetAclInformation
#define ADVAPI32$GetAce                     GetAce
#define ADVAPI32$MapGenericMask             MapGenericMask
#define ADVAPI32$InitializeSecurityDescriptor InitializeSecurityDescriptor
#define ADVAPI32$SetSecurityDescriptorDacl  SetSecurityDescriptorDacl
#define ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorW \
                                            ConvertSecurityDescriptorToStringSecurityDescriptorW
#define ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorW \
                                            ConvertStringSecurityDescriptorToSecurityDescriptorW
#define ADVAPI32$StartServiceA              StartServiceA
#define ADVAPI32$ControlService             ControlService
#define ADVAPI32$EnumDependentServicesA     EnumDependentServicesA
#define ADVAPI32$CryptAcquireContextA       CryptAcquireContextA
#define ADVAPI32$CryptCreateHash            CryptCreateHash
#define ADVAPI32$CryptReleaseContext        CryptReleaseContext
#define ADVAPI32$CryptHashData              CryptHashData
#define ADVAPI32$CryptGetHashParam          CryptGetHashParam
#define ADVAPI32$CryptDestroyHash           CryptDestroyHash
#define ADVAPI32$RegGetKeySecurity          RegGetKeySecurity
#define ADVAPI32$RegSetKeySecurity          RegSetKeySecurity
#define ADVAPI32$SetEntriesInAclA           SetEntriesInAclA
#define NTDLL$NtCreateFile                  NtCreateFile
#define NTDLL$NtClose                       NtClose
#define NTDLL$NtFsControlFile               NtFsControlFile
#define IMAGEHLP$ImageEnumerateCertificates ImageEnumerateCertificates
#define IMAGEHLP$ImageGetCertificateHeader  ImageGetCertificateHeader
#define IMAGEHLP$ImageGetCertificateData    ImageGetCertificateData
#define CRYPT32$CryptVerifyMessageSignature CryptVerifyMessageSignature
#define CRYPT32$CertGetNameStringW          CertGetNameStringW
#define CRYPT32$CertCreateCertificateContext CertCreateCertificateContext
#define CRYPT32$CertFreeCertificateContext  CertFreeCertificateContext
#define CRYPT32$CertGetCertificateContextProperty CertGetCertificateContextProperty
#define CRYPT32$CertGetCertificateChain     CertGetCertificateChain
#define CRYPT32$CertFreeCertificateChain    CertFreeCertificateChain
#define CRYPT32$CryptFindOIDInfo            CryptFindOIDInfo
#define OLE32$CoInitializeEx                CoInitializeEx
#define OLE32$CoUninitialize                CoUninitialize
#define OLE32$CoInitializeSecurity          CoInitializeSecurity
#define OLE32$CoCreateInstance              CoCreateInstance
#define OLE32$CLSIDFromString               CLSIDFromString
#define OLE32$IIDFromString                 IIDFromString
#define OLE32$StringFromGUID2               StringFromGUID2
#define OLE32$CoSetProxyBlanket             CoSetProxyBlanket
#define OLE32$CoTaskMemAlloc                CoTaskMemAlloc
#define OLE32$CoTaskMemFree                 CoTaskMemFree
#define OLEAUT32$SysAllocString             SysAllocString
#define OLEAUT32$SysReAllocString           SysReAllocString
#define OLEAUT32$SysFreeString              SysFreeString
#define OLEAUT32$SysStringLen               SysStringLen
#define OLEAUT32$VariantInit                VariantInit
#define OLEAUT32$VariantClear               VariantClear
#define OLEAUT32$VariantChangeType          VariantChangeType
#define OLEAUT32$SafeArrayDestroy           SafeArrayDestroy
#define OLEAUT32$SafeArrayLock              SafeArrayLock
#define OLEAUT32$SafeArrayGetLBound         SafeArrayGetLBound
#define OLEAUT32$SafeArrayGetUBound         SafeArrayGetUBound
#define OLEAUT32$SafeArrayGetElement        SafeArrayGetElement
#define OLEAUT32$SafeArrayGetElemsize       SafeArrayGetElemsize
#define OLEAUT32$SafeArrayAccessData        SafeArrayAccessData
#define OLEAUT32$SafeArrayUnaccessData      SafeArrayUnaccessData
#define BCRYPT$BCryptOpenAlgorithmProvider  BCryptOpenAlgorithmProvider
#define BCRYPT$BCryptCloseAlgorithmProvider BCryptCloseAlgorithmProvider
#define BCRYPT$BCryptSetProperty            BCryptSetProperty
#define BCRYPT$BCryptGenerateSymmetricKey   BCryptGenerateSymmetricKey
#define BCRYPT$BCryptDestroyKey             BCryptDestroyKey
#define BCRYPT$BCryptDecrypt                BCryptDecrypt
#define BCRYPT$BCryptCreateHash             BCryptCreateHash
#define BCRYPT$BCryptDestroyHash            BCryptDestroyHash
#define BCRYPT$BCryptHashData               BCryptHashData
#define BCRYPT$BCryptFinishHash             BCryptFinishHash
#define DBGHELP$MiniDumpWriteDump           MiniDumpWriteDump
#define WLDAP32$ldap_init                   ldap_init
#define WLDAP32$ldap_bind_s                 ldap_bind_s
#define WLDAP32$ldap_search_s               ldap_search_s
#define WLDAP32$ldap_count_entries          ldap_count_entries
#define WLDAP32$ldap_get_values_lenA        ldap_get_values_lenA
#define WLDAP32$ldap_value_free_len         ldap_value_free_len
#define WLDAP32$ldap_set_optionA            ldap_set_optionA
#define WLDAP32$ldap_search_init_pageA      ldap_search_init_pageA
#define WLDAP32$ldap_get_paged_count        ldap_get_paged_count
#define WLDAP32$ldap_get_next_page_s        ldap_get_next_page_s
#define WLDAP32$ldap_first_entry            ldap_first_entry
#define WLDAP32$ldap_next_entry             ldap_next_entry
#define WLDAP32$ldap_first_attribute        ldap_first_attribute
#define WLDAP32$ldap_count_values           ldap_count_values
#define WLDAP32$ldap_get_values             ldap_get_values
#define WLDAP32$ldap_value_free             ldap_value_free
#define WLDAP32$ldap_next_attribute         ldap_next_attribute
#define WLDAP32$ber_free                    ber_free
#define WLDAP32$ber_bvfree                  ber_bvfree
#define WLDAP32$ldap_memfree                ldap_memfree
#define WLDAP32$ldap_unbind                 ldap_unbind
#define WLDAP32$ldap_unbind_s               ldap_unbind_s
#define WLDAP32$ldap_msgfree                ldap_msgfree
#define WLDAP32$ldap_initW                  ldap_initW
#define WLDAP32$ldap_connect                ldap_connect
#define WLDAP32$ldap_set_optionW            ldap_set_optionW
#define WLDAP32$ldap_get_optionW            ldap_get_optionW
#define WLDAP32$ldap_sasl_bind_sW           ldap_sasl_bind_sW
#define RPCRT4$UuidToStringA                UuidToStringA
#define RPCRT4$RpcStringFreeA               RpcStringFreeA
#define PSAPI$EnumProcessModulesEx          EnumProcessModulesEx
#define PSAPI$GetModuleFileNameExA          GetModuleFileNameExA
#define VERSION$GetFileVersionInfoSizeA     GetFileVersionInfoSizeA
#define VERSION$GetFileVersionInfoA         GetFileVersionInfoA
#define VERSION$VerQueryValueA              VerQueryValueA
#define BeaconPrintf(x, y, ...)             printf(y, ##__VA_ARGS__)
#define internal_printf                     printf

#endif /* BOF */

/* =========================================================================
 * Beacon API function declarations (implemented in beacon_compatibility.c)
 * ========================================================================= */
#ifdef _WIN32

/* Dispatch table populated at startup (index 29 = __C_specific_handler) */
extern unsigned char* InternalFunctions[30][2];

void   BeaconDataParse(datap* parser, char* buffer, int size);
int    BeaconDataInt(datap* parser);
short  BeaconDataShort(datap* parser);
int    BeaconDataLength(datap* parser);
char*  BeaconDataExtract(datap* parser, int* size);

void   BeaconFormatAlloc(formatp* format, int maxsz);
void   BeaconFormatReset(formatp* format);
void   BeaconFormatFree(formatp* format);
void   BeaconFormatAppend(formatp* format, char* text, int len);
void   BeaconFormatPrintf(formatp* format, char* fmt, ...);
char*  BeaconFormatToString(formatp* format, int* size);
void   BeaconFormatInt(formatp* format, int value);

void   BeaconPrintf(int type, char* fmt, ...);
void   BeaconOutput(int type, char* data, int len);

/* Retrieve (and reset) the accumulated output buffer.
 * Caller owns the returned pointer and must free() it. */
char*  BeaconGetOutputData(int* outsize);

BOOL   BeaconUseToken(HANDLE token);
void   BeaconRevertToken(void);
BOOL   BeaconIsAdmin(void);

void   BeaconGetSpawnTo(BOOL x86, char* buffer, int length);
BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                   STARTUPINFO* sInfo, PROCESS_INFORMATION* pInfo);
void   BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len,
                           int p_offset, char* arg, int a_len);
void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload,
                                    int p_len, int p_offset, char* arg, int a_len);
void   BeaconCleanupProcess(PROCESS_INFORMATION* pInfo);

BOOL   toWideChar(char* src, wchar_t* dst, int max);

#endif /* _WIN32 */

#endif /* BEACON_COMPATIBILITY_H_ */