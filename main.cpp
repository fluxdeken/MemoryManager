#include "stdafx.h"
#include "process.h"

int main()
{
	PROCESS processObj;
	PPROCESS process = &processObj;

	process->open(L"notepad.exe");
	// process->showMemInfo(process->baseAddr);
	// if (process->injectMM(L"test.dll")) dlog("Manual mapping: Success\n");
	// if (process->inject(L"test.dll")) dlog("Injecting: Success\n");
	// if (process->eject(L"test.dll")) dlog("Ejecting: Success\n");
	
	process->close();
    return 0;
}

