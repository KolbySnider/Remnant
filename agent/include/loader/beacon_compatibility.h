/*
 * beacon_compatibility.h  –  BOF-side compatibility header
 *
 * Provides everything a BOF compiled against base.c needs when running
 * inside the standalone hardened loader (not a real Cobalt Strike Beacon).
 *
 * v3 changes
 * ──────────
 * [CASE]    Added KERNEL32$ (all-caps) aliases for every Kernel32$ entry.
 *           TrustedSec BOFs use KERNEL32$ consistently; the previous header
 *           only defined mixed-case Kernel32$ causing "implicit declaration"
 *           warnings and integer-return crashes on every BOF in the repo.
 *
 * [SECUR32] Added SECUR32$ thunk block.  sysinfo.c uses
 *           SECUR32$GetUserNameExA; without this it was an implicit int
 *           declaration, silently returning garbage on x64.
 *
 * [NAMETYPE] NameSamCompatible is defined in <secext.h> which requires
 *           <security.h> first.  Both are included here so BOFs that use
 *           EXTENDED_NAME_FORMAT values compile without errors.
 *
 * [IPHLPAPI] Added IPHLPAPI$ thunk block for arp_cache and similar BOFs.
 *
 * [WS2_32]  Added WS2_32$ thunk block for inet_ntoa, inet_addr, etc.
 *
 * [NTDLL]   Expanded NTDLL$ block with RtlMoveMemory and other commonly
 *           used NT functions.
 *
 * [REDEF]   COFFLoader.h defines IMAGE_SYM_CLASS_* and winnt.h also defines
 *           them.  Guard the defines with #ifndef so including both headers
 *           in the same translation unit produces no warnings.
 */

#pragma once
#ifndef BEACON_COMPATIBILITY_H
#define BEACON_COMPATIBILITY_H

#ifdef _WIN32
/* winsock2.h MUST be first — windows.h pulls in the older winsock.h which
 * conflicts with winsock2.h types if windows.h is included first. */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
/* security.h / secext.h (via sspi.h) #error without SECURITY_WIN32.
 * Define it before including either header. */
#ifndef SECURITY_WIN32
#  define SECURITY_WIN32
#endif
#include <security.h>
#include <secext.h>
#include <sddl.h>
/* For MIB_IPNETTABLE, MIB_TCPTABLE, GetIpNetTable, GetTcpTable */
#include <iphlpapi.h>

#ifndef BOF
#  define BOF
#endif

#define CALLBACK_OUTPUT       0
#define CALLBACK_ERROR        0x0d
#define CALLBACK_OUTPUT_OEM   0x1e
#define CALLBACK_OUTPUT_UTF8  0x20

#define intAlloc(size)           HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size))
#define intFree(addr)            HeapFree(GetProcessHeap(), 0, (addr))
#define intZeroMemory(addr,size) SecureZeroMemory((addr),(size))

#define MSVCRT$calloc        calloc
#define MSVCRT$malloc        malloc
#define MSVCRT$realloc       realloc
#define MSVCRT$free          free
#define MSVCRT$memcpy        memcpy
#define MSVCRT$memset        memset
#define MSVCRT$memcmp        memcmp
#define MSVCRT$memmove       memmove
#define MSVCRT$strlen        strlen
#define MSVCRT$strcpy        strcpy
#define MSVCRT$strncpy       strncpy
#define MSVCRT$strcmp        strcmp
#define MSVCRT$strncmp       strncmp
#define MSVCRT$strcat        strcat
#define MSVCRT$strncat       strncat
#define MSVCRT$strchr        strchr
#define MSVCRT$strrchr       strrchr
#define MSVCRT$strstr        strstr
#define MSVCRT$sprintf       sprintf
#define MSVCRT$snprintf      snprintf
#define MSVCRT$vsprintf      vsprintf
#define MSVCRT$vsnprintf     vsnprintf
#define MSVCRT$printf        printf
#define MSVCRT$fprintf       fprintf
#define MSVCRT$sscanf        sscanf
#define MSVCRT$atoi          atoi
#define MSVCRT$atol          atol
#define MSVCRT$atof          atof
#define MSVCRT$strtol        strtol
#define MSVCRT$strtoul       strtoul
#define MSVCRT$strtod        strtod
#define MSVCRT$_stricmp      _stricmp
#define MSVCRT$_strnicmp     _strnicmp
#define MSVCRT$wcslen        wcslen
#define MSVCRT$wcscpy        wcscpy
#define MSVCRT$wcscat        wcscat
#define MSVCRT$wcscmp        wcscmp
#define MSVCRT$_wcsicmp      _wcsicmp

#define Kernel32$GetProcessHeap            GetProcessHeap
#define Kernel32$HeapAlloc                 HeapAlloc
#define Kernel32$HeapFree                  HeapFree
#define Kernel32$HeapReAlloc               HeapReAlloc
#define Kernel32$VirtualAlloc              VirtualAlloc
#define Kernel32$VirtualAllocEx            VirtualAllocEx
#define Kernel32$VirtualFree               VirtualFree
#define Kernel32$VirtualFreeEx             VirtualFreeEx
#define Kernel32$VirtualProtect            VirtualProtect
#define Kernel32$VirtualProtectEx          VirtualProtectEx
#define Kernel32$VirtualQuery              VirtualQuery
#define Kernel32$VirtualQueryEx            VirtualQueryEx
#define Kernel32$WriteProcessMemory        WriteProcessMemory
#define Kernel32$ReadProcessMemory         ReadProcessMemory
#define Kernel32$LoadLibraryA              LoadLibraryA
#define Kernel32$LoadLibraryW              LoadLibraryW
#define Kernel32$GetProcAddress            GetProcAddress
#define Kernel32$GetModuleHandleA          GetModuleHandleA
#define Kernel32$GetModuleHandleW          GetModuleHandleW
#define Kernel32$FreeLibrary               FreeLibrary
#define Kernel32$CloseHandle               CloseHandle
#define Kernel32$CreateFileA               CreateFileA
#define Kernel32$CreateFileW               CreateFileW
#define Kernel32$ReadFile                  ReadFile
#define Kernel32$WriteFile                 WriteFile
#define Kernel32$GetFileSize               GetFileSize
#define Kernel32$GetFileSizeEx             GetFileSizeEx
#define Kernel32$DeleteFileA               DeleteFileA
#define Kernel32$DeleteFileW               DeleteFileW
#define Kernel32$CopyFileA                 CopyFileA
#define Kernel32$MoveFileA                 MoveFileA
#define Kernel32$CreateDirectoryA          CreateDirectoryA
#define Kernel32$RemoveDirectoryA          RemoveDirectoryA
#define Kernel32$GetTempPathA              GetTempPathA
#define Kernel32$GetTempFileNameA          GetTempFileNameA
#define Kernel32$GetCurrentDirectoryA      GetCurrentDirectoryA
#define Kernel32$SetCurrentDirectoryA      SetCurrentDirectoryA
#define Kernel32$GetSystemDirectoryA       GetSystemDirectoryA
#define Kernel32$GetWindowsDirectoryA      GetWindowsDirectoryA
#define Kernel32$WideCharToMultiByte       WideCharToMultiByte
#define Kernel32$MultiByteToWideChar       MultiByteToWideChar
#define Kernel32$GetLastError              GetLastError
#define Kernel32$SetLastError              SetLastError
#define Kernel32$FormatMessageA            FormatMessageA
#define Kernel32$FormatMessageW            FormatMessageW
#define Kernel32$LocalAlloc                LocalAlloc
#define Kernel32$LocalFree                 LocalFree
#define Kernel32$LocalReAlloc              LocalReAlloc
#define Kernel32$GlobalAlloc               GlobalAlloc
#define Kernel32$GlobalFree                GlobalFree
#define Kernel32$OpenProcess               OpenProcess
#define Kernel32$TerminateProcess          TerminateProcess
#define Kernel32$GetCurrentProcess         GetCurrentProcess
#define Kernel32$GetCurrentProcessId       GetCurrentProcessId
#define Kernel32$GetCurrentThread          GetCurrentThread
#define Kernel32$GetCurrentThreadId        GetCurrentThreadId
#define Kernel32$OpenThread                OpenThread
#define Kernel32$TerminateThread           TerminateThread
#define Kernel32$CreateThread              CreateThread
#define Kernel32$WaitForSingleObject       WaitForSingleObject
#define Kernel32$WaitForMultipleObjects    WaitForMultipleObjects
#define Kernel32$Sleep                     Sleep
#define Kernel32$GetTickCount              GetTickCount
#define Kernel32$QueryPerformanceCounter   QueryPerformanceCounter
#define Kernel32$QueryPerformanceFrequency QueryPerformanceFrequency
#define Kernel32$GetComputerNameA          GetComputerNameA
#define Kernel32$GetComputerNameExA        GetComputerNameExA
#define Kernel32$GetComputerNameExW        GetComputerNameExW
#define Kernel32$GetUserNameA              GetUserNameA
#define Kernel32$IsWow64Process            IsWow64Process
#define Kernel32$GlobalMemoryStatusEx      GlobalMemoryStatusEx
#define Kernel32$GetSystemInfo             GetSystemInfo
#define Kernel32$GetNativeSystemInfo       GetNativeSystemInfo
#define Kernel32$GetVersionExA             GetVersionExA
#define Kernel32$CreateToolhelp32Snapshot  CreateToolhelp32Snapshot
#define Kernel32$Process32First            Process32First
#define Kernel32$Process32Next             Process32Next
#define Kernel32$Process32FirstW           Process32FirstW
#define Kernel32$Process32NextW            Process32NextW
#define Kernel32$Thread32First             Thread32First
#define Kernel32$Thread32Next              Thread32Next
#define Kernel32$Module32First             Module32First
#define Kernel32$Module32Next              Module32Next
#define Kernel32$FindFirstFileA            FindFirstFileA
#define Kernel32$FindNextFileA             FindNextFileA
#define Kernel32$FindClose                 FindClose
#define Kernel32$GetFileAttributesA        GetFileAttributesA
#define Kernel32$SetFileAttributesA        SetFileAttributesA
#define Kernel32$GetFullPathNameA          GetFullPathNameA
#define Kernel32$ExpandEnvironmentStringsA ExpandEnvironmentStringsA
#define Kernel32$CreatePipe                CreatePipe
#define Kernel32$SetHandleInformation      SetHandleInformation
#define Kernel32$PeekNamedPipe             PeekNamedPipe
#define Kernel32$CreateProcessA            CreateProcessA
#define Kernel32$CreateProcessW            CreateProcessW
#define Kernel32$DuplicateHandle           DuplicateHandle
#define Kernel32$SetFilePointer            SetFilePointer
#define Kernel32$FlushFileBuffers          FlushFileBuffers
#define Kernel32$GetExitCodeProcess        GetExitCodeProcess
#define Kernel32$GetExitCodeThread         GetExitCodeThread
#define Kernel32$ResumeThread              ResumeThread
#define Kernel32$SuspendThread             SuspendThread
#define Kernel32$SetThreadContext          SetThreadContext
#define Kernel32$GetThreadContext          GetThreadContext
#define Kernel32$OpenProcessToken          OpenProcessToken

#define KERNEL32$GetProcessHeap            Kernel32$GetProcessHeap
#define KERNEL32$HeapAlloc                 Kernel32$HeapAlloc
#define KERNEL32$HeapFree                  Kernel32$HeapFree
#define KERNEL32$HeapReAlloc               Kernel32$HeapReAlloc
#define KERNEL32$VirtualAlloc              Kernel32$VirtualAlloc
#define KERNEL32$VirtualAllocEx            Kernel32$VirtualAllocEx
#define KERNEL32$VirtualFree               Kernel32$VirtualFree
#define KERNEL32$VirtualFreeEx             Kernel32$VirtualFreeEx
#define KERNEL32$VirtualProtect            Kernel32$VirtualProtect
#define KERNEL32$VirtualProtectEx          Kernel32$VirtualProtectEx
#define KERNEL32$VirtualQuery              Kernel32$VirtualQuery
#define KERNEL32$VirtualQueryEx            Kernel32$VirtualQueryEx
#define KERNEL32$WriteProcessMemory        Kernel32$WriteProcessMemory
#define KERNEL32$ReadProcessMemory         Kernel32$ReadProcessMemory
#define KERNEL32$LoadLibraryA              Kernel32$LoadLibraryA
#define KERNEL32$LoadLibraryW              Kernel32$LoadLibraryW
#define KERNEL32$GetProcAddress            Kernel32$GetProcAddress
#define KERNEL32$GetModuleHandleA          Kernel32$GetModuleHandleA
#define KERNEL32$GetModuleHandleW          Kernel32$GetModuleHandleW
#define KERNEL32$FreeLibrary               Kernel32$FreeLibrary
#define KERNEL32$CloseHandle               Kernel32$CloseHandle
#define KERNEL32$CreateFileA               Kernel32$CreateFileA
#define KERNEL32$CreateFileW               Kernel32$CreateFileW
#define KERNEL32$ReadFile                  Kernel32$ReadFile
#define KERNEL32$WriteFile                 Kernel32$WriteFile
#define KERNEL32$GetFileSize               Kernel32$GetFileSize
#define KERNEL32$GetFileSizeEx             Kernel32$GetFileSizeEx
#define KERNEL32$DeleteFileA               Kernel32$DeleteFileA
#define KERNEL32$DeleteFileW               Kernel32$DeleteFileW
#define KERNEL32$CopyFileA                 Kernel32$CopyFileA
#define KERNEL32$MoveFileA                 Kernel32$MoveFileA
#define KERNEL32$CreateDirectoryA          Kernel32$CreateDirectoryA
#define KERNEL32$RemoveDirectoryA          Kernel32$RemoveDirectoryA
#define KERNEL32$GetTempPathA              Kernel32$GetTempPathA
#define KERNEL32$GetTempFileNameA          Kernel32$GetTempFileNameA
#define KERNEL32$GetCurrentDirectoryA      Kernel32$GetCurrentDirectoryA
#define KERNEL32$SetCurrentDirectoryA      Kernel32$SetCurrentDirectoryA
#define KERNEL32$GetSystemDirectoryA       Kernel32$GetSystemDirectoryA
#define KERNEL32$GetWindowsDirectoryA      Kernel32$GetWindowsDirectoryA
#define KERNEL32$WideCharToMultiByte       Kernel32$WideCharToMultiByte
#define KERNEL32$MultiByteToWideChar       Kernel32$MultiByteToWideChar
#define KERNEL32$GetLastError              Kernel32$GetLastError
#define KERNEL32$SetLastError              Kernel32$SetLastError
#define KERNEL32$FormatMessageA            Kernel32$FormatMessageA
#define KERNEL32$FormatMessageW            Kernel32$FormatMessageW
#define KERNEL32$LocalAlloc                Kernel32$LocalAlloc
#define KERNEL32$LocalFree                 Kernel32$LocalFree
#define KERNEL32$LocalReAlloc              Kernel32$LocalReAlloc
#define KERNEL32$GlobalAlloc               Kernel32$GlobalAlloc
#define KERNEL32$GlobalFree                Kernel32$GlobalFree
#define KERNEL32$OpenProcess               Kernel32$OpenProcess
#define KERNEL32$TerminateProcess          Kernel32$TerminateProcess
#define KERNEL32$GetCurrentProcess         Kernel32$GetCurrentProcess
#define KERNEL32$GetCurrentProcessId       Kernel32$GetCurrentProcessId
#define KERNEL32$GetCurrentThread          Kernel32$GetCurrentThread
#define KERNEL32$GetCurrentThreadId        Kernel32$GetCurrentThreadId
#define KERNEL32$OpenThread                Kernel32$OpenThread
#define KERNEL32$TerminateThread           Kernel32$TerminateThread
#define KERNEL32$CreateThread              Kernel32$CreateThread
#define KERNEL32$WaitForSingleObject       Kernel32$WaitForSingleObject
#define KERNEL32$WaitForMultipleObjects    Kernel32$WaitForMultipleObjects
#define KERNEL32$Sleep                     Kernel32$Sleep
#define KERNEL32$GetTickCount              Kernel32$GetTickCount
#define KERNEL32$QueryPerformanceCounter   Kernel32$QueryPerformanceCounter
#define KERNEL32$QueryPerformanceFrequency Kernel32$QueryPerformanceFrequency
#define KERNEL32$GetComputerNameA          Kernel32$GetComputerNameA
#define KERNEL32$GetComputerNameExA        Kernel32$GetComputerNameExA
#define KERNEL32$GetComputerNameExW        Kernel32$GetComputerNameExW
#define KERNEL32$GetUserNameA              Kernel32$GetUserNameA
#define KERNEL32$IsWow64Process            Kernel32$IsWow64Process
#define KERNEL32$GlobalMemoryStatusEx      Kernel32$GlobalMemoryStatusEx
#define KERNEL32$GetSystemInfo             Kernel32$GetSystemInfo
#define KERNEL32$GetNativeSystemInfo       Kernel32$GetNativeSystemInfo
#define KERNEL32$GetVersionExA             Kernel32$GetVersionExA
#define KERNEL32$CreateToolhelp32Snapshot  Kernel32$CreateToolhelp32Snapshot
#define KERNEL32$Process32First            Kernel32$Process32First
#define KERNEL32$Process32Next             Kernel32$Process32Next
#define KERNEL32$Process32FirstW           Kernel32$Process32FirstW
#define KERNEL32$Process32NextW            Kernel32$Process32NextW
#define KERNEL32$Thread32First             Kernel32$Thread32First
#define KERNEL32$Thread32Next              Kernel32$Thread32Next
#define KERNEL32$Module32First             Kernel32$Module32First
#define KERNEL32$Module32Next              Kernel32$Module32Next
#define KERNEL32$FindFirstFileA            Kernel32$FindFirstFileA
#define KERNEL32$FindNextFileA             Kernel32$FindNextFileA
#define KERNEL32$FindClose                 Kernel32$FindClose
#define KERNEL32$GetFileAttributesA        Kernel32$GetFileAttributesA
#define KERNEL32$SetFileAttributesA        Kernel32$SetFileAttributesA
#define KERNEL32$GetFullPathNameA          Kernel32$GetFullPathNameA
#define KERNEL32$ExpandEnvironmentStringsA Kernel32$ExpandEnvironmentStringsA
#define KERNEL32$CreatePipe                Kernel32$CreatePipe
#define KERNEL32$SetHandleInformation      Kernel32$SetHandleInformation
#define KERNEL32$PeekNamedPipe             Kernel32$PeekNamedPipe
#define KERNEL32$CreateProcessA            Kernel32$CreateProcessA
#define KERNEL32$CreateProcessW            Kernel32$CreateProcessW
#define KERNEL32$DuplicateHandle           Kernel32$DuplicateHandle
#define KERNEL32$SetFilePointer            Kernel32$SetFilePointer
#define KERNEL32$FlushFileBuffers          Kernel32$FlushFileBuffers
#define KERNEL32$GetExitCodeProcess        Kernel32$GetExitCodeProcess
#define KERNEL32$GetExitCodeThread         Kernel32$GetExitCodeThread
#define KERNEL32$ResumeThread              Kernel32$ResumeThread
#define KERNEL32$SuspendThread             Kernel32$SuspendThread
#define KERNEL32$SetThreadContext          Kernel32$SetThreadContext
#define KERNEL32$GetThreadContext          Kernel32$GetThreadContext
#define KERNEL32$OpenProcessToken          Kernel32$OpenProcessToken

#define NTDLL$RtlAllocateHeap       RtlAllocateHeap
#define NTDLL$RtlFreeHeap           RtlFreeHeap
#define NTDLL$RtlZeroMemory         RtlZeroMemory
#define NTDLL$RtlCopyMemory         RtlCopyMemory
#define NTDLL$RtlMoveMemory         RtlMoveMemory
#define NTDLL$RtlFillMemory         RtlFillMemory
#define NTDLL$RtlCompareMemory      RtlCompareMemory
#define NTDLL$NtQuerySystemInformation NtQuerySystemInformation
#define NTDLL$NtQueryInformationProcess NtQueryInformationProcess
#define NTDLL$NtQueryInformationThread  NtQueryInformationThread

#define SECUR32$GetUserNameExA      GetUserNameExA
#define SECUR32$GetUserNameExW      GetUserNameExW

#define IPHLPAPI$GetIpNetTable      GetIpNetTable
#define IPHLPAPI$GetIpNetTable2     GetIpNetTable2
#define IPHLPAPI$GetTcpTable        GetTcpTable
#define IPHLPAPI$GetTcpTable2       GetTcpTable2
#define IPHLPAPI$GetUdpTable        GetUdpTable
#define IPHLPAPI$GetAdaptersInfo    GetAdaptersInfo
#define IPHLPAPI$GetAdaptersAddresses GetAdaptersAddresses
#define IPHLPAPI$GetIfTable         GetIfTable
#define IPHLPAPI$GetIfEntry         GetIfEntry
#define IPHLPAPI$GetIpAddrTable     GetIpAddrTable
#define IPHLPAPI$GetIpForwardTable  GetIpForwardTable

#define WS2_32$inet_ntoa            inet_ntoa
#define WS2_32$inet_addr            inet_addr
#define WS2_32$htons                htons
#define WS2_32$ntohs                ntohs
#define WS2_32$htonl                htonl
#define WS2_32$ntohl                ntohl
#define WS2_32$WSAStartup           WSAStartup
#define WS2_32$WSACleanup           WSACleanup
#define WS2_32$socket               socket
#define WS2_32$connect              connect
#define WS2_32$send                 send
#define WS2_32$recv                 recv
#define WS2_32$closesocket          closesocket
#define WS2_32$WSAGetLastError      WSAGetLastError
#define WS2_32$getaddrinfo          getaddrinfo
#define WS2_32$freeaddrinfo         freeaddrinfo

#define ADVAPI32$OpenProcessToken       OpenProcessToken
#define ADVAPI32$GetTokenInformation    GetTokenInformation
#define ADVAPI32$LookupAccountSidA      LookupAccountSidA
#define ADVAPI32$LookupPrivilegeNameA   LookupPrivilegeNameA
#define ADVAPI32$LookupPrivilegeValueA  LookupPrivilegeValueA
#define ADVAPI32$AdjustTokenPrivileges  AdjustTokenPrivileges
#define ADVAPI32$ImpersonateLoggedOnUser ImpersonateLoggedOnUser
#define ADVAPI32$RevertToSelf           RevertToSelf
#define ADVAPI32$RegOpenKeyExA          RegOpenKeyExA
#define ADVAPI32$RegQueryValueExA       RegQueryValueExA
#define ADVAPI32$RegCloseKey            RegCloseKey
#define ADVAPI32$CreateServiceA         CreateServiceA
#define ADVAPI32$OpenServiceA           OpenServiceA
#define ADVAPI32$StartServiceA          StartServiceA
#define ADVAPI32$ControlService         ControlService
#define ADVAPI32$DeleteService          DeleteService
#define ADVAPI32$OpenSCManagerA         OpenSCManagerA
#define ADVAPI32$CloseServiceHandle     CloseServiceHandle
#define ADVAPI32$AllocateAndInitializeSid AllocateAndInitializeSid
#define ADVAPI32$CheckTokenMembership   CheckTokenMembership
#define ADVAPI32$FreeSid                FreeSid
#define ADVAPI32$ConvertSidToStringSidA ConvertSidToStringSidA
#define ADVAPI32$ConvertSidToStringSidW ConvertSidToStringSidW

typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

void  BeaconDataParse(datap* parser, char* buffer, int size);
int   BeaconDataInt(datap* parser);
short BeaconDataShort(datap* parser);
int   BeaconDataLength(datap* parser);
char* BeaconDataExtract(datap* parser, int* size);

typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} formatp;

void  BeaconFormatAlloc(formatp* format, int maxsz);
void  BeaconFormatReset(formatp* format);
void  BeaconFormatFree(formatp* format);
void  BeaconFormatAppend(formatp* format, char* text, int len);
void  BeaconFormatPrintf(formatp* format, char* fmt, ...);
char* BeaconFormatToString(formatp* format, int* size);
void  BeaconFormatInt(formatp* format, int value);

void  BeaconPrintf(int type, char* fmt, ...);
void  BeaconOutput(int type, char* data, int len);
char* BeaconGetOutputData(int* outsize);

BOOL  BeaconUseToken(HANDLE token);
void  BeaconRevertToken(void);
BOOL  BeaconIsAdmin(void);
void  BeaconGetSpawnTo(BOOL x86, char* buffer, int length);
BOOL  BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                  STARTUPINFO* sInfo,
                                  PROCESS_INFORMATION* pInfo);
void  BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len,
                          int p_offset, char* arg, int a_len);
void  BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo,
                                   char* payload, int p_len,
                                   int p_offset, char* arg, int a_len);
void  BeaconCleanupProcess(PROCESS_INFORMATION* pInfo);
BOOL  toWideChar(char* src, wchar_t* dst, int max);

void* CoffResolveExport(const char* lib_name, const char* func_name);

void InitInternalFunctions(void);

#endif /* _WIN32 */
#endif /* BEACON_COMPATIBILITY_H */