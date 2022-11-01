#include "Memory.h"
#include <stdio.h>

BYTE* Memory::getModule(char* moduleName, DWORD pId, DWORD* moduleSize)
{
	
	HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pId);
	if (snapShot == INVALID_HANDLE_VALUE)
	{
		printf("[-] Module snapshot failed : 0x%x\n", GetLastError());
		return 0;
	}

	MODULEENTRY32 mInfo;
	mInfo.dwSize = sizeof(MODULEENTRY32);
	Module32First(snapShot, &mInfo);

	do
	{
		// Convert to lower to ease comparison
		for (size_t i = 0; i < strlen(moduleName); i++)
		{
			if (isupper(moduleName[i]))
				moduleName[i] = tolower(moduleName[i]);
		}

		for (size_t i = 0; i < strlen(mInfo.szModule); i++)
		{
			if(isupper(mInfo.szModule[i]))
				mInfo.szModule[i] = tolower(mInfo.szModule[i]);
		}

		if (strcmp(mInfo.szModule, moduleName) == 0)
		{
			CloseHandle(snapShot); 
			*moduleSize = mInfo.modBaseSize;
			return mInfo.modBaseAddr;
		}
			
	} while (Module32Next(snapShot, &mInfo));

	printf("[-] %s is not a loaded module\n", moduleName); system("PAUSE");
	CloseHandle(snapShot);
	return 0;
}

bool Memory::getModuleExportHeaders(BYTE* moduleBase, PDLL_EXPORTS dllExp) // Will either take a pointer to a dll read in from disk or from other process.
{
	dllExp->pDosHeaders = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);
	// Check if valid PE
	if (dllExp->pDosHeaders->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[-] Invalid PE\n"); system("PAUSE");
		return false;
	}

	dllExp->pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(moduleBase + dllExp->pDosHeaders->e_lfanew);
	dllExp->pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(moduleBase + dllExp->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	dllExp->addressOfNames = reinterpret_cast<PDWORD>(moduleBase + dllExp->pExportDir->AddressOfNames);
	dllExp->addressOfFunctions = reinterpret_cast<PDWORD>(moduleBase + dllExp->pExportDir->AddressOfFunctions);
	dllExp->addressOfNameOrdinals = reinterpret_cast<PWORD>(moduleBase + dllExp->pExportDir->AddressOfNameOrdinals);
	
	return true;
}

std::vector<BYTE> Memory::readDllInOtherProcessIntoMemory(HANDLE hProc, BYTE* moduleBase, DWORD moduleSize)
{
	std::vector<BYTE> loadedModule(moduleSize);

	// Read from base into vector
	if (!ReadProcessMemory(hProc, moduleBase, &loadedModule[0], moduleSize, 0))
	{
		printf("[-] Failed to read module into memory : 0x%x\n", GetLastError()); system("PAUSE");
		return {};
	}

	// Return data
	return loadedModule;
}

std::vector<BYTE> Memory::readDllFromDiskIntoMemory(const char* dllPath)
{
	// Open dll file and seek to eof
	std::ifstream File(dllPath, std::ios::binary | std::ios::ate);
	if (File.fail()) {
		printf("[-] Opening the file failed\n"); system("PAUSE");
		File.close(); 
		return {};
	}

	// Check if filesize is valid by getting the position of the current character in the input stream (at eof)
	auto FileSize = File.tellg();
	if (FileSize < 0x1000) {
		printf("[-] Filesize invalid.\n"); system("PAUSE");
		File.close(); 
		return {};
	}

	std::vector<BYTE> dllOnDisk(FileSize);

	// Seek back to the beginning, read entire file into vector.
	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(&dllOnDisk[0]), FileSize);
	File.close();
	
	return dllOnDisk;
}

DWORD Memory::getPidFromProcName(const char* procName)
{
	HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapShot == INVALID_HANDLE_VALUE)
	{
		printf("[-] Module snapshot failed : 0x%x\n", GetLastError());
		return 0;
	}

	PROCESSENTRY32 procInfo;
	procInfo.dwSize = sizeof(PROCESSENTRY32);
	Process32First(snapShot, &procInfo);

	do
	{
		if (strcmp(procInfo.szExeFile, procName) == 0)
		{
			CloseHandle(snapShot); return procInfo.th32ProcessID;
		}
			
	} while (Process32Next(snapShot, &procInfo));

	CloseHandle(snapShot);
	printf("[-] Failed to find PID\n"); system("PAUSE");
	return 0;

}