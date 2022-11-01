#include "Scanner.h"
#include "Memory.h"
#include <iostream>


void Scanner::scanModule(BYTE* imageBase, BYTE* imageBaseLoaded)
{
	DLL_EXPORTS dllFromDisk, dllInMemory;
	ZeroMemory(&dllFromDisk, sizeof(dllFromDisk)); ZeroMemory(&dllInMemory, sizeof(dllInMemory));
	
	if (
		!Memory::getModuleExportHeaders(imageBaseLoaded, &dllInMemory) || !Memory::getModuleExportHeaders(imageBase, &dllFromDisk))
		return;

	int amount = 0;
	// Compare the dll from disk versus the one loaded into memory
	for (size_t i = 0; i < dllFromDisk.pExportDir->NumberOfNames; i++)
	{
		// If the one on disk doesn't start with 0xE9 (jmp) but the one in memory does, a hook has been put in place.
		if (*reinterpret_cast<BYTE*>(imageBase + dllFromDisk.addressOfFunctions[dllFromDisk.addressOfNameOrdinals[i]]) != 0xE9 	// !!! Use the ordinal number as index in the function address array. NOT i!.
			&& *reinterpret_cast<BYTE*>(imageBaseLoaded + dllInMemory.addressOfFunctions[dllInMemory.addressOfNameOrdinals[i]]) == 0xE9)
			{
				printf("[+] Hook detected at %s\n", imageBaseLoaded + dllInMemory.addressOfNames[i]);
				amount++;
			}				
	}

	if (amount > 0)
		printf("[!] %d hook/s has been installed\n\n", amount);
	else
		printf("[!] No hooks detected\n\n");

	return;
}

