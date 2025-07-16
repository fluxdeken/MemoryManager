#include "stdafx.h"

#define HEX(oneByte) std::uppercase << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>((oneByte) & 0xFF) << L" "

void dlog(const char* format, ...);

std::string wstring_to_utf8(const wchar_t* data);

std::string wstring_to_ansi(const wchar_t* data);

typedef class _PROCESS {
private:
	HANDLE hProcess;
	UINT procId;
	ULONG_PTR moduleSize;

	bool attach() {
		if (procId == 0) return false;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, procId);
		if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
			dlog("Opening handle: failed.\n");
			return false;
		}
		dlog("Opening handle: success.\n");
		return true;
	}

	bool getProcId(const wchar_t* procName) {
		HANDLE hSnap = CreateToolhelp32Snapshot(
			TH32CS_SNAPPROCESS, NULL);
		if (!hSnap || hSnap == INVALID_HANDLE_VALUE) return false;
		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnap, &pe)) {
			do {
				if (_wcsicmp(procName, pe.szExeFile) == 0) {
					CloseHandle(hSnap);
					procId = pe.th32ProcessID;
					dlog("Process id: %u\n", procId);
					return true;
				}
			} while (Process32Next(hSnap, &pe));
		}
		CloseHandle(hSnap);
		return false;
	}

	bool getBaseAddr(const wchar_t* modName) {
		if (procId == 0) return false;
		HANDLE hSnap = CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
			procId);
		if (!hSnap || hSnap == INVALID_HANDLE_VALUE) return false;
		MODULEENTRY32 me;
		me.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnap, &me)) {
			do {
				if (_wcsicmp(modName, me.szModule) == 0) {
					CloseHandle(hSnap);
					moduleSize = me.modBaseSize;
					dlog("Module size: %u\n", moduleSize);
					baseAddr = (ULONG_PTR)me.modBaseAddr;
					return true;
				}
			} while (Module32Next(hSnap, &me));
		}
		CloseHandle(hSnap);
		return false;
	}

	inline void ApplyRelocations(BYTE* mapped_image, PIMAGE_NT_HEADERS64 nt, ULONGLONG actual_base) {
		auto& reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (reloc_dir.VirtualAddress == 0) return; // no relocations

		ULONGLONG delta = actual_base - nt->OptionalHeader.ImageBase;
		if (delta == 0) return;

		auto reloc = (PIMAGE_BASE_RELOCATION)(mapped_image + reloc_dir.VirtualAddress);
		DWORD size = 0;

		while (size < reloc_dir.Size && reloc->SizeOfBlock) {
			DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* reloc_data = (WORD*)(reloc + 1);

			for (DWORD i = 0; i < count; ++i) {
				WORD type_offset = reloc_data[i];
				WORD type = type_offset >> 12;
				WORD offset = type_offset & 0xFFF;

				if (type == IMAGE_REL_BASED_DIR64) {
					ULONGLONG* patch = (ULONGLONG*)(mapped_image + reloc->VirtualAddress + offset);
					*patch += delta;
				}
			}

			size += reloc->SizeOfBlock;
			reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
		}
	}

	inline bool ResolveImports(BYTE* mapped_image, PIMAGE_NT_HEADERS64 nt) {
		//auto& import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (import_dir.VirtualAddress == 0) return false;

		auto import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(mapped_image + import_dir.VirtualAddress);

		while (import_desc->Name) {
			const char* dll_name = (const char*)(mapped_image + import_desc->Name);
			HMODULE dll = LoadLibraryA(dll_name);
			if (!dll) return false;

			auto thunk_ref = (ULONGLONG*)(mapped_image + import_desc->OriginalFirstThunk);
			auto func_ref = (ULONGLONG*)(mapped_image + import_desc->FirstThunk);

			if (!import_desc->OriginalFirstThunk) // if no INT, use IAT
				thunk_ref = func_ref;

			while (*thunk_ref) {
				FARPROC func = nullptr;
				if (IMAGE_SNAP_BY_ORDINAL(*thunk_ref)) {
					func = GetProcAddress(dll, (LPCSTR)(*thunk_ref & 0xFFFF));
				}
				else {
					auto import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(mapped_image + (*thunk_ref));
					func = GetProcAddress(dll, (LPCSTR)import_by_name->Name);
				}

				if (!func) return false;
				*func_ref = (ULONGLONG)func;

				++thunk_ref;
				++func_ref;
			}

			++import_desc;
		}

		return true;
	}

	inline void RunTLSCallbacks(BYTE* mapped_image, PIMAGE_NT_HEADERS64 nt, ULONGLONG remote_base) {
		auto& tlsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (tlsDir.VirtualAddress == 0 || tlsDir.Size == 0)
			return;

		auto tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY64>(mapped_image + tlsDir.VirtualAddress);

		ULONGLONG original_base = nt->OptionalHeader.ImageBase;
		ULONGLONG delta = remote_base - original_base;

		ULONGLONG callbacksVA = tls->AddressOfCallBacks;
		if (callbacksVA == 0)
			return;

		ULONGLONG relocatedCallbacksVA = callbacksVA + delta;

		// Читаем массив колбэков из памяти удалённого процесса
		SIZE_T ptrSize = sizeof(void*);
		std::vector<ULONGLONG> callbacksVec;

		for (size_t i = 0;; ++i) {
			ULONGLONG callbackAddr = 0;
			SIZE_T bytesRead = 0;
			BOOL res = ReadProcessMemory(
				hProcess,
				(LPCVOID)(relocatedCallbacksVA + i * ptrSize),
				&callbackAddr,
				ptrSize,
				&bytesRead
			);

			if (!res || bytesRead != ptrSize || callbackAddr == 0)
				break;

			callbacksVec.push_back(callbackAddr);
		}

		// Запускаем callbacks
		for (ULONGLONG addr : callbacksVec) {
			auto callback = reinterpret_cast<PIMAGE_TLS_CALLBACK>(addr);
			callback((LPVOID)remote_base, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	inline DWORD GetExportRVA(const char* funcName, BYTE* dllBase)
	{
		auto dos = (PIMAGE_DOS_HEADER)dllBase;
		auto nt = (PIMAGE_NT_HEADERS64)(dllBase + dos->e_lfanew);
		auto& exportDirData = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (exportDirData.VirtualAddress == 0)
			return 0;

		auto exportDir = (PIMAGE_EXPORT_DIRECTORY)(dllBase + exportDirData.VirtualAddress);

		DWORD* names = (DWORD*)(dllBase + exportDir->AddressOfNames);
		WORD* ordinals = (WORD*)(dllBase + exportDir->AddressOfNameOrdinals);
		DWORD* functions = (DWORD*)(dllBase + exportDir->AddressOfFunctions);

		for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
			const char* currName = (const char*)(dllBase + names[i]);
			if (strcmp(currName, funcName) == 0) {
				WORD ordinal = ordinals[i];
				DWORD funcRVA = functions[ordinal];
				return funcRVA;
			}
		}

		return 0; // not found
	}


public:
	ULONG_PTR baseAddr;

	_PROCESS():hProcess(nullptr), procId(0), 
		baseAddr(0), moduleSize(0) {}

	void open(const wchar_t* procName) {
		clear();

		if (getProcId(procName)) {
			getBaseAddr(procName);
			attach();
		}
	}

	void open(const wchar_t* procName, const wchar_t* modName) {
		clear();

		if (getProcId(procName)) {
			getBaseAddr(modName);
			attach();
		}
	}

	bool is_attached() {
		if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
			return true;
		}
		dlog("Handle: closed.\n");
		return false;
	}

	void showMemInfo(ULONG_PTR addr) {
		if (is_attached()) {
			MEMORY_BASIC_INFORMATION mbi;
			if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
				dlog("memInfo:\n");
				dlog("--BaseAddr: 0x%p\n", ULONG_PTR(mbi.BaseAddress));
				dlog("--AllocationBase: 0x%p\n", ULONG_PTR(mbi.AllocationBase));
				dlog("--AllocationProtect: 0x%X\n", mbi.AllocationProtect);
#if defined _M_X64
				dlog("--PartitionId: %d\n", mbi.PartitionId);
#endif
				dlog("--RegionSize: 0x%p\n", (ULONG_PTR)mbi.RegionSize);
				dlog("--State: 0x%X\n", mbi.State);
				dlog("--Protect: 0x%X\n", mbi.Protect);
				dlog("--Type: 0x%X\n", mbi.Type);
			}
		}
	}

	bool getMemInfo(ULONG_PTR addr, PMEMORY_BASIC_INFORMATION mbi) {
		if (!is_attached()) return false;

		if (VirtualQueryEx(hProcess, (LPCVOID)addr, mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
			return true;
		}
		else {
			dlog("getMemInfo: failed\n");
			return false;
		}
	}

	bool isRegionReadable(PMEMORY_BASIC_INFORMATION mbi) {
		if (mbi->State == MEM_COMMIT &&
			!(mbi->Protect & PAGE_GUARD) &&
			!(mbi->Protect & PAGE_NOACCESS)) {
			return true;
		}
		return false;
	}

	ULONG_PTR findPattern(const char* ptrn, size_t ptrnSz) {

		if (!is_attached()) return 0;

		const size_t limit = moduleSize - ptrnSz - 1;

		std::vector<char> buff;
		buff.resize(moduleSize);
		//std::unique_ptr<char[]> buff(new char[moduleSize]);

		ReadProcessMemory(hProcess, (LPCVOID)baseAddr, buff.data(), moduleSize, nullptr);

		for (ULONG_PTR i = 0; i < limit; i++) {
			if (buff[i] == ptrn[0] &&
				memcmp(buff.data(), &ptrn[0], ptrnSz - 1) == 0)
			{
				ULONG_PTR output = baseAddr + i;
				return output;
			}
		}
		return 0;
	}

	uintptr_t PatternScan(const char* ptrn, size_t ptrnSz,
		const char* mask) {

		if (!is_attached()) return 0;

		const size_t limit = moduleSize - ptrnSz - 1;

		std::vector<char> buff;
		buff.resize(moduleSize);
		// std::unique_ptr<char[]> buff(new char[moduleSize]);

		ReadProcessMemory(hProcess, (LPCVOID)baseAddr, buff.data(), moduleSize, nullptr);

		for (size_t i = 0; i < limit; ++i) {
			bool found = true;
			for (size_t j = 0; mask[j]; ++j) {
				if (mask[j] != '?' && ptrn[j] != buff[i + j]) {
					found = false;
					break;
				}
			}
			if (found) {
				uintptr_t result = baseAddr + i;
				return result;
			}
		}
		return 0;
	}

	template<typename T>
	bool patch(ULONG_PTR addr, const T* buff, ULONG buffSize) {
		if (!is_attached()) return false;
		WriteProcessMemory(hProcess, (LPVOID)addr, buff, buffSize, nullptr);
		return true;
	}

	ULONG_PTR getAddrByOffset(const ULONG_PTR* offsets, ULONG size) {

		if (!is_attached()) return 0;

		ULONG_PTR address = baseAddr;
		ULONG_PTR value = 0;

		for (ULONG i = 0; i < size - 1; i++) {
			address += offsets[i];

			ReadProcessMemory(hProcess, (LPCVOID)address,
				&value, sizeof(ULONG_PTR), nullptr);

			address = value;
		}

		value += offsets[size - 1];
		dlog("Address: %u\n", value);
		return value;
	}

	template<typename T>
	bool getAddrVal (ULONG_PTR address, T* value) {
		if (!is_attached()) return false;
		ReadProcessMemory(hProcess, (LPCVOID)address, value, sizeof(T), nullptr);
		return true;
	}

	bool getAddrBytes(ULONG_PTR addr, ULONG_PTR amount, BYTE* buff) {
		if (!is_attached()) return false;
		ReadProcessMemory(hProcess, (LPVOID)addr, buff, amount, nullptr);
		return true;
	}


	// Modified injectMM to use hardcoded shellcode instead of ReflectiveLoader
	int injectMM(const wchar_t* dllname) {
		if (!is_attached()) {
			dlog("Manual mapping: not attached\n");
			return 0;
		}

		WCHAR cwd[MAX_PATH];
		GetCurrentDirectory(MAX_PATH, cwd);

		std::wstring fPath = std::wstring(cwd) + L"\\" + dllname;

		std::ifstream fin(fPath, std::ios::binary | std::ios::ate);
		if (fin.fail()) {
			dlog("Manual mapping: failed opening DLL\n");
			return 0;
		}

		uintptr_t size = fin.tellg();
		fin.seekg(0, std::ios::beg);
		std::vector<BYTE> buff(size);
		fin.read(reinterpret_cast<char*>(buff.data()), size);
		fin.close();

		BYTE* base = buff.data();
		auto dos = (PIMAGE_DOS_HEADER)base;
		auto nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
		auto sect_header = IMAGE_FIRST_SECTION(nt);
		WORD number_of_sections = nt->FileHeader.NumberOfSections;

		std::vector<BYTE> mapped_image(nt->OptionalHeader.SizeOfImage);
		memcpy(mapped_image.data(), base, nt->OptionalHeader.SizeOfHeaders);

		for (int i = 0; i < number_of_sections; ++i) {
			BYTE* dest = mapped_image.data() + sect_header[i].VirtualAddress;
			BYTE* src = base + sect_header[i].PointerToRawData;
			size_t size = std::min<size_t>(sect_header[i].SizeOfRawData, sect_header[i].Misc.VirtualSize);
			memcpy(dest, src, size);
		}

		void* remote_mem = VirtualAllocEx(hProcess, nullptr, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!remote_mem) {
			dlog("Manual mapping: Allocation failed.\n");
			return 0;
		}

		ApplyRelocations(mapped_image.data(), nt, (ULONGLONG)remote_mem);
		if (!ResolveImports(mapped_image.data(), nt)) {
			std::cout << "Error resolving imports\n";
		}

		WriteProcessMemory(hProcess, remote_mem, mapped_image.data(), nt->OptionalHeader.SizeOfImage, nullptr);

		//RunTLSCallbacks(mapped_image.data(), nt, (ULONGLONG)remote_mem);

		// Replace reflective loader call with shellcode
		/*unsigned char ShellcodeWithoutTLS[] = {
			0x48, 0x63, 0x41, 0x3C, 0x45, 0x33, 0xC0, 0xBA,
			0x01, 0x00, 0x00, 0x00, 0x44, 0x8B, 0x4C, 0x08,
			0x28, 0x4C, 0x03, 0xC9, 0x49, 0xFF, 0xE1
		};*/
		unsigned char Shellcode[] = {
			0x40, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89,
			0x74, 0x24, 0x38, 0x48, 0x8B, 0xF9, 0x48, 0x63,
			0x71, 0x3C, 0x8B, 0x84, 0x0E, 0xD0, 0x00, 0x00,
			0x00, 0x85, 0xC0, 0x74, 0x42, 0x83, 0xBC, 0x0E,
			0xD4, 0x00, 0x00, 0x00, 0x00, 0x74, 0x38, 0x48,
			0x89, 0x5C, 0x24, 0x30, 0x48, 0x8B, 0x5C, 0x08,
			0x18, 0x48, 0x85, 0xDB, 0x74, 0x24, 0x48, 0x8B,
			0x03, 0x48, 0x85, 0xC0, 0x74, 0x1C, 0x66, 0x90,
			0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00,
			0x48, 0x8B, 0xCF, 0xFF, 0xD0, 0x48, 0x8B, 0x43,
			0x08, 0x48, 0x8D, 0x5B, 0x08, 0x48, 0x85, 0xC0,
			0x75, 0xE6, 0x48, 0x8B, 0x5C, 0x24, 0x30, 0x8B,
			0x44, 0x3E, 0x28, 0x48, 0x8B, 0x74, 0x24, 0x38,
			0x85, 0xC0, 0x74, 0x16, 0x48, 0x03, 0xC7, 0x45,
			0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48,
			0x8B, 0xCF, 0x48, 0x83, 0xC4, 0x20, 0x5F, 0x48,
			0xFF, 0xE0, 0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3 };

		void* remote_shellcode = VirtualAllocEx(hProcess, nullptr, sizeof(Shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!remote_shellcode) {
			dlog("Manual mapping: Shellcode allocation failed\n");
			return 0;
		}

		WriteProcessMemory(hProcess, remote_shellcode, Shellcode, sizeof(Shellcode), nullptr);

		CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)remote_shellcode, remote_mem, 0, nullptr);
		dlog("Manual mapping: Success\n");
		return 1;
	}


	bool inject(const wchar_t* dllname) {
		if (!is_attached()) {
			return false;
		}
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
		if (hSnap == INVALID_HANDLE_VALUE) return false;

		MODULEENTRY32 me;
		me.dwSize = sizeof(MODULEENTRY32);

		bool foundKernel = false;

		// Finding offset
		HMODULE localKernel32 = GetModuleHandle(L"kernel32.dll");
		FARPROC localLoadLibrary = GetProcAddress(localKernel32, "LoadLibraryA");
		uintptr_t offset = (uintptr_t)localLoadLibrary - (uintptr_t)localKernel32;

		// Remote Kernel32
		HMODULE remoteKernel32 = nullptr;
		LPVOID remoteLoadLibraryAddr = nullptr;

		HMODULE remoteDllAddr = nullptr;

		if (Module32First(hSnap, &me)) {
			do {
				if (_wcsicmp(me.szModule, L"kernel32.dll") == 0) {
					remoteKernel32 = me.hModule;
					remoteLoadLibraryAddr = (LPVOID)((uintptr_t)remoteKernel32 + offset);
					foundKernel = true;
				}
			} while (Module32Next(hSnap, &me));
		}

		CloseHandle(hSnap);


		wchar_t cwd[MAX_PATH];
		GetCurrentDirectoryW(MAX_PATH, cwd);
		std::wstring fPath(cwd);
		fPath += L"\\";
		fPath += dllname;

		std::string utf8dllPath = wstring_to_utf8(fPath.c_str());
		SIZE_T bytesWritten = 0;

		if (foundKernel && remoteLoadLibraryAddr) {

			size_t utf8dllPathSize = utf8dllPath.length() + 1;

			LPVOID Memory = VirtualAllocEx(hProcess, NULL, utf8dllPathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			WriteProcessMemory(hProcess, (LPVOID)Memory, utf8dllPath.c_str(), utf8dllPathSize, &bytesWritten);

			dlog("Dll path: %s\nbytesWritten: %u\n", utf8dllPath.c_str(), bytesWritten);

			HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL,
				(LPTHREAD_START_ROUTINE)remoteLoadLibraryAddr,
				Memory, 0, NULL);

			if (hThread) {
				CloseHandle(hThread);
				dlog("Injecting: Success\n");
				return true;
			}
		}
		dlog("Injecting: Failure\n");
		return false;
	}

	bool eject(const wchar_t* dllname) {
		if (!is_attached()) return false;

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
		if (hSnap == INVALID_HANDLE_VALUE) return false;

		MODULEENTRY32 me;
		me.dwSize = sizeof(MODULEENTRY32);

		bool foundKernel = false;

		// Finding offset
		HMODULE localKernel32 = GetModuleHandle(L"kernel32.dll");
		FARPROC localFreeLibrary = GetProcAddress(localKernel32, "FreeLibrary");
		uintptr_t offset = (uintptr_t)localFreeLibrary - (uintptr_t)localKernel32;

		// Remote Kernel32
		HMODULE remoteKernel32 = nullptr;
		LPVOID remoteFreeLibraryAddr = nullptr;

		HMODULE remoteDllAddr = nullptr;

		if (Module32First(hSnap, &me)) {
			do {
				if (_wcsicmp(me.szModule, L"kernel32.dll") == 0) {
					remoteKernel32 = me.hModule;
					remoteFreeLibraryAddr = (LPVOID)((uintptr_t)remoteKernel32 + offset);
					foundKernel = true;
				}
				else if (_wcsicmp(dllname, me.szModule) == 0) { // dll found
					remoteDllAddr = me.hModule;
				}
			} while (Module32Next(hSnap, &me));
		}

		CloseHandle(hSnap);

		if (remoteFreeLibraryAddr && remoteDllAddr) {
			HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
				(LPTHREAD_START_ROUTINE)remoteFreeLibraryAddr,
				remoteDllAddr, 0, NULL);
			if (hThread) {
				CloseHandle(hThread);
				dlog("Ejectinng: Success\n");
				return true;
			}
		}
		dlog("Ejectinng: Failure\n");
		return false;
	}

	void clear() {
		if (is_attached()) CloseHandle(hProcess);

		hProcess = nullptr;
		procId = 0;
		baseAddr = 0;
		moduleSize = 0;
	}
	void close() {
		if (is_attached()) CloseHandle(hProcess);

		hProcess = nullptr;
		procId = 0;
		baseAddr = 0;
		moduleSize = 0;
	}

	~_PROCESS() {
		clear();
	}

} PROCESS, * PPROCESS;