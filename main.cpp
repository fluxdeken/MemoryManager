#include "stdafx.h"
#include "process.h"

int main()
{
	PROCESS process;

	process.open(L"test_d3d9_win32.exe");

	// process.inject(L"test.hook.dll");
	// process.eject(L"test.hook.dll");
	// process.injectMM(L"test.dll");
	// process.inject(L"test_dll.dll");
	process.injectMM(L"test.dll");
	process.close();

    return 0;
}

