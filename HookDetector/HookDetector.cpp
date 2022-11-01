#include "Memory.h"
#include "Scanner.h"
#include "targets.h"
#include <string>

int main(int argc, char** argv)
{		
	if (argc < 2)
	{
		printf("Example usage : 'mspaint.exe'\n"); system("PAUSE");
		return 1;
	}
	
	char procName[128];
	if (strlen(argv[1]) + 1 > 128)
	{
		printf("Invalid Process name!\n"); system("PAUSE");
		return 1;
	}

	memcpy(procName, argv[1], strlen(argv[1])+1);
	DWORD pId = Memory::getPidFromProcName(procName);
	if (!pId)
		return 1;
	
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);
	if (hProc == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open process : 0x%x\n", GetLastError());
		system("PAUSE");
		return 1;
	}
	
	HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pId);
	if (snapShot == INVALID_HANDLE_VALUE)
	{
		printf("[-] Module snapshot failed : 0x%x\n", GetLastError());
		return 0;
	}
	
	MODULEENTRY32 mInfo;
	mInfo.dwSize = sizeof(MODULEENTRY32);
	Module32First(snapShot, &mInfo);

	printf("--- %s ---\n\n", procName);

	do
	{	
		// Check if current module is the on we're targeting
		for (size_t i = 0; i < strlen(mInfo.szModule); i++)
			mInfo.szModule[i] = isupper(mInfo.szModule[i]) ? tolower(mInfo.szModule[i]) : mInfo.szModule[i];	
		if (!std::count(targets.begin(), targets.end(), mInfo.szModule))
			continue;
				
		std::vector<BYTE> dllOnDisk = Memory::readDllFromDiskIntoMemory(mInfo.szExePath);
		if (dllOnDisk.empty())
			return 1;

		std::vector<BYTE> loadedModule = Memory::readDllInOtherProcessIntoMemory(hProc, mInfo.modBaseAddr, mInfo.modBaseSize);
		if (loadedModule.empty())
			return 1;
		
		printf("(%s)\n", mInfo.szExePath);
		Scanner::scanModule(&dllOnDisk[0], &loadedModule[0]);

	} while (Module32Next(snapShot, &mInfo));

	CloseHandle(hProc);
	CloseHandle(snapShot);
	
	printf("[!] Hookscanning done [!]\n"); system("PAUSE");

	return 0;
}


