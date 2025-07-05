#include <iostream>
#include <windows.h>
#include <shobjidl.h>
#include <tlhelp32.h>
#include <fstream>
#include <string>
#include <vector>

#include <sstream>
#include <iomanip>

#define HEX(oneByte) std::uppercase << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>((oneByte) & 0xFF) << L" "

void dLog(const char* format, ...);

std::string wstring_to_utf8(const wchar_t* data);

std::string wstring_to_ansi(const wchar_t* data);

typedef class _PROCESS {
private:
	HANDLE hProcess;
	UINT procId;

	ULONG_PTR baseAddr;
	ULONG_PTR moduleSize;

	bool attach() {
		if (procId == 0) return false;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, procId);
		if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
			dLog("Opening handle: failed.\n");
			return false;
		}
		dLog("Opening handle: success.\n");
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
					dLog("Process id: %u\n", procId);
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
					dLog("Module size: %u\n", moduleSize);
					baseAddr = (ULONG_PTR)me.modBaseAddr;
					return true;
				}
			} while (Module32Next(hSnap, &me));
		}
		CloseHandle(hSnap);
		return false;
	}

	void ApplyRelocations(BYTE* mapped_image, PIMAGE_OPTIONAL_HEADER64 opt_header, ULONGLONG actual_base) {
		auto& reloc_dir = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (reloc_dir.VirtualAddress == 0) return; // no relocations

		ULONGLONG delta = actual_base - opt_header->ImageBase;
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

	bool ResolveImports(BYTE* mapped_image, PIMAGE_OPTIONAL_HEADER64 opt_header) {
		//auto& import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		auto& import_dir = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
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

public:
	_PROCESS() {}
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
			dLog("Handle: opened.\n");
			return true;
		}
		dLog("Handle: closed.\n");
		return false;
	}

	ULONG_PTR findPattern(const char* ptrn, size_t ptrnSz) {

		if (!is_attached()) return 0;

		const size_t limit = moduleSize - ptrnSz - 1;

		std::vector<char> buffer;
		buffer.resize(moduleSize);

		ReadProcessMemory(hProcess, (LPCVOID)baseAddr, &buffer[0], moduleSize, nullptr);

		for (ULONG_PTR i = 0; i < limit; i++) {
			if (buffer[i] == ptrn[0] &&
				memcmp(&buffer[i], &ptrn[0], ptrnSz - 1) == 0)
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

		std::vector<char> buffer;
		buffer.resize(moduleSize);

		ReadProcessMemory(hProcess, (LPCVOID)baseAddr, &buffer[0], moduleSize, nullptr);

		for (size_t i = 0; i < limit; ++i) {
			bool found = true;
			for (size_t j = 0; mask[j]; ++j) {
				if (mask[j] != '?' && ptrn[j] != buffer[i + j]) {
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

	ULONG_PTR getPointer(const ULONG_PTR* offsets, ULONG size) {

		if (!is_attached()) return 0;

		ULONG_PTR address = baseAddr;
		ULONG_PTR value = 0;

		for (ULONG i = 0; i < size - 1; i++) {
			address += offsets[i];
			//bool result = 
			ReadProcessMemory(hProcess, (LPCVOID)address,
				&value, sizeof(ULONG_PTR), nullptr);
			//if(!result) return 0;
			address = value;
		}

		value += offsets[size - 1];
		dLog("Address: %u\n", value);
		return value;
	}

	template<typename T>
	bool getPointerValue(ULONG_PTR address, T* value) {
		if (!is_attached()) return false;
		ReadProcessMemory(hProcess, (LPCVOID)address, value, sizeof(T), nullptr);
		return true;
	}

	bool readBytes(ULONG_PTR addr, ULONG amount, std::vector<BYTE>& buff) {
		if (!is_attached()) return false;
		if (!buff.empty()) buff.clear();
		buff.resize(amount);
		ReadProcessMemory(hProcess, (LPVOID)addr, buff.data(), amount, nullptr);
		return true;
	}

	int ManualMap(const char* dllName) {

		if (!is_attached()) return -1;

		char cwd[MAX_PATH];
		GetCurrentDirectoryA(MAX_PATH, cwd);

		std::string fPath(cwd);
		fPath += "\\";
		fPath += dllName;

		std::ifstream fin(fPath.c_str(), std::ios::binary | std::ios::ate);
		if (fin.fail()) return 1;

		uintptr_t size = fin.tellg();
		fin.seekg(0L, std::ios::beg);

		std::vector<BYTE> buff(size);
		fin.read(reinterpret_cast<char*>(buff.data()), size);
		fin.close();

		BYTE* base = buff.data();

		PIMAGE_DOS_HEADER dosect_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base);

		uintptr_t shift = dosect_header->e_lfanew;

		PIMAGE_NT_HEADERS64 nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(base + shift);

		shift += 4;
		PIMAGE_FILE_HEADER file_header = reinterpret_cast<PIMAGE_FILE_HEADER>(base + shift);

		shift += sizeof(IMAGE_FILE_HEADER);
		PIMAGE_OPTIONAL_HEADER64 opt_header = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(base + shift);

		// shift += sizeof(IMAGE_OPTIONAL_HEADER64);

		//PIMAGE_SECTION_HEADER sect_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(base + shift);
		PIMAGE_SECTION_HEADER sect_header = IMAGE_FIRST_SECTION(nt_headers);

		WORD number_of_sections = file_header->NumberOfSections;


		// Allocating and setting memory to 0's
		BYTE* mapped_image = new BYTE[opt_header->SizeOfImage];
		memset(mapped_image, 0, opt_header->SizeOfImage);

		// Copying headers
		memcpy(mapped_image, base, opt_header->SizeOfHeaders);

		// Copying sections
		for (int i = 0; i < number_of_sections; ++i) {
			BYTE* dest = mapped_image + sect_header[i].VirtualAddress;
			BYTE* src = base + sect_header[i].PointerToRawData;
			size_t size = sect_header[i].SizeOfRawData;
			memcpy(dest, src, size);
		}

		ApplyRelocations(mapped_image, opt_header, (ULONGLONG)mapped_image);

		if (!ResolveImports(mapped_image, opt_header)) {
			dLog("Failed to resolve imports\n");
		}


		// Final steps
		unsigned char Shellcode[] = {
		0x48, 0x63, 0x41, 0x3C, 0x45, 0x33, 0xC0, 0xBA,
		0x01, 0x00, 0x00, 0x00, 0x44, 0x8B, 0x4C, 0x08,
		0x28, 0x4C, 0x03, 0xC9, 0x49, 0xFF, 0xE1
		};

		SIZE_T totalSize = opt_header->SizeOfImage + sizeof(Shellcode); // 0x1000 — запас под shell
		void* remote_mem = VirtualAllocEx(hProcess, nullptr, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		// void* address = VirtualAllocEx(hProc, nullptr, opt_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (remote_mem == NULL) {
			delete[] mapped_image;
			dLog("Allocation failed.\n");
			return 0;
		}

		WriteProcessMemory(hProcess, (void*)remote_mem, mapped_image, opt_header->SizeOfImage, nullptr);

		void* shellcode_remote_addr = (BYTE*)remote_mem + opt_header->SizeOfImage;
		WriteProcessMemory(hProcess, (void*)shellcode_remote_addr, Shellcode, sizeof(Shellcode), nullptr);

		CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)shellcode_remote_addr, remote_mem, 0, nullptr);

		delete[] mapped_image;
		return 0;
	}

	bool inject(const wchar_t* dllPath) {
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
		fPath += dllPath;

		std::string utf8dllPath = wstring_to_utf8(fPath.c_str());
		SIZE_T bytesWritten = 0;

		if (foundKernel && remoteLoadLibraryAddr) {

			size_t utf8dllPathSize = utf8dllPath.length() + 1;

			LPVOID Memory = VirtualAllocEx(hProcess, NULL, utf8dllPathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			WriteProcessMemory(hProcess, (LPVOID)Memory, utf8dllPath.c_str(), utf8dllPathSize, &bytesWritten);

			dLog("Dll path: %s\nbytesWritten: %u\n", utf8dllPath.c_str(), bytesWritten);

			HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL,
				(LPTHREAD_START_ROUTINE)remoteLoadLibraryAddr,
				Memory, 0, NULL);

			if (hThread) {
				CloseHandle(hThread);
				return true;
			}
		}
		return false;
	}

	bool eject(const wchar_t* dllName) {
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
				else if (_wcsicmp(dllName, me.szModule) == 0) { // dll found
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
				return true;
			}
			else {
				return false;
			}
		}

		return false;
	}

	void clear() {
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