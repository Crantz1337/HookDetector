#pragma once
#include <string>
#include <vector>

// !! A read access violation occurs while attempting to get the export header of some dlls if the dll has been read in from disk, like C:\Windows\System32\Windows.UI.Xaml.Controls.dll !!
std::vector<std::string> targets = {
	"kernel32.dll", // Case doesn't matter
	"ntdll.dll",
	"user32.dll",
	"advapi32.dll"
};