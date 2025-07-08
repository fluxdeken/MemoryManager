#include "stdafx.h"
#include "process.h"

typedef int (WINAPI* MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);

// Pointer for calling original MessageBoxW.
MESSAGEBOXW fpMessageBoxW = NULL;

int WINAPI DetourMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	//return fpMessageBoxW(hWnd, L"Hooked!", lpCaption, uType);
	dlog("Detour function\n");
	return 0;
}

template <typename OriginalFuncType, typename DetourFuncType>
void CreateMinHook(
	OriginalFuncType pTarget,
	DetourFuncType pDetour,
	OriginalFuncType* ppOriginal)
{
	MH_Initialize();

	MH_CreateHook(
		reinterpret_cast<LPVOID>(pTarget),
		reinterpret_cast<LPVOID>(pDetour),
		reinterpret_cast<LPVOID*>(ppOriginal)
	);

	MH_EnableHook(pTarget);
}

int main()
{
	PROCESS processObj;
	PPROCESS process = &processObj;

	MessageBox(NULL, L"Smthg", L"Info", MB_OK);

	CreateMinHook(&MessageBoxW, &DetourMessageBoxW, &fpMessageBoxW);

	MessageBox(NULL, L"Smthg", L"Info", MB_OK);

	MH_DisableHook(&MessageBoxW);

	MH_Uninitialize();

	MessageBox(NULL, L"Smthg", L"Info", MB_OK);

	process->open(L"notepad.exe");
	// process->showMemInfo(process->baseAddr);
	// if (process->injectMM(L"DLL_Injected.dll")) dlog("Manual mapping: Success\n");
	// if (process->inject(L"test.dll")) dlog("Injecting: Success\n");
	// if (process->eject(L"test.dll")) dlog("Ejecting: Success\n");
	
	if (process->inject(L"test.dll")) dlog("Manual mapping: Success\n");
	process->close();
    return 0;
}

