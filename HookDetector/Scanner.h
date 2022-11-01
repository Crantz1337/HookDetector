#pragma once
#include <Windows.h>
#include <tlhelp32.h>

static class Scanner
{
public:
	static void scanModule(BYTE* imageBase, BYTE* imageBaseLoaded);
};




