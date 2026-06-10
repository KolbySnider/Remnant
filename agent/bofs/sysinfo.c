#include <windows.h>
#include "beacon_compatibility.h"
#include "base.c"

#ifdef BOF
VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	if(!bofstart())
	{
		return;
	}

	/* ---------- buffers ---------- */
	WCHAR wComputer[256];
	char  computer[256];
	char  username[256];

	DWORD sizeW;
	DWORD sizeA;

	SYSTEM_INFO si;
	OSVERSIONINFOA osvi;
	MEMORYSTATUSEX mem;

	internal_printf("\n=== SYSTEM INFORMATION ===\n\n");

	/* ---------- Computer Name ---------- */
	sizeW = 256;

	if (KERNEL32$GetComputerNameExW(
			ComputerNameNetBIOS,
			wComputer,
			&sizeW))
	{
		Kernel32$WideCharToMultiByte(
			CP_ACP,
			0,
			wComputer,
			-1,
			computer,
			sizeof(computer),
			NULL,
			NULL
		);

		internal_printf("Computer Name: %s\n", computer);
	}

	/* ---------- Username ---------- */
	sizeA = sizeof(username);

	if (SECUR32$GetUserNameExA(NameSamCompatible, username, &sizeA))
	{
		internal_printf("Username: %s\n", username);
	}

	/* ---------- Memory ---------- */
	mem.dwLength = sizeof(MEMORYSTATUSEX);

	if (KERNEL32$GlobalMemoryStatusEx(&mem))
	{
		internal_printf(
			"Total RAM: %.2f GB\n",
			(double)mem.ullTotalPhys / (1024.0 * 1024.0 * 1024.0)
		);

		internal_printf(
			"Available RAM: %.2f GB\n",
			(double)mem.ullAvailPhys / (1024.0 * 1024.0 * 1024.0)
		);
	}

	internal_printf("\n=== END ===\n");

	printoutput(TRUE);
}
#else
int main()
{
	//code for standalone exe for scanbuild / leak checks
	return 0;
}
#endif