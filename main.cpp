#include "stdafx.h"
#include "process.h"

int main()
{
	PROCESS process;

	process.open(L"test.exe");

	// process.inject(L"test.hook.dll");
	// process.eject(L"test.hook.dll");

	process.injectMM(L"test.hook.dll");
	process.close();

    return 0;
}

