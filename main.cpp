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

	process->open(L"notepad.exe");
	process->inject(L"test.dll");
	// process->showMemInfo(process->baseAddr);
	// process->injectMM(L"DLL_Injected.dll");
	// process->eject(L"test.dll");
	process->close();

	/*MessageBox(NULL, L"Smthg", L"Info", MB_OK);

	CreateMinHook(&MessageBoxW, &DetourMessageBoxW, &fpMessageBoxW);

	MessageBox(NULL, L"Smthg", L"Info", MB_OK);

	MH_DisableHook(&MessageBoxW);

	MH_Uninitialize();

	MessageBox(NULL, L"Smthg", L"Info", MB_OK);*/

    return 0;
}

