#include "stdafx.h"
#include "process.h"

int main()
{
	PROCESS process;

	process.open(L"d3d9_win32_release.exe");
	process.inject(L"d3d9hook_release.dll");
	process.close();

    return 0;
}

