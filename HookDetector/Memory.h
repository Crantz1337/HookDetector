#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <vector>

typedef struct _DLL_EXPORTS
{
	IMAGE_DOS_HEADER* pDosHeaders;
	IMAGE_NT_HEADERS* pNtHeaders;
	PIMAGE_EXPORT_DIRECTORY pExportDir;
	PDWORD addressOfNames;
	PDWORD addressOfFunctions;
	PWORD addressOfNameOrdinals; // !!! each ordinal is a WORD

} DLL_EXPORTS, * PDLL_EXPORTS;

static class Memory
{		
public:
	static BYTE* getModule(char* moduleName, DWORD pId, DWORD* moduleSize);
	static std::vector<BYTE> readDllFromDiskIntoMemory(const char* dllPath);
	static std::vector<BYTE> readDllInOtherProcessIntoMemory(HANDLE hProc, BYTE* moduleBase, DWORD moduleSize);
	static bool getModuleExportHeaders(BYTE* moduleBase, PDLL_EXPORTS dllExp);	
	static DWORD getPidFromProcName(const char* procName);
};

