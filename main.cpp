#include "process.h"

int main()
{
	PROCESS processObj;
	PPROCESS process = &processObj;

	process->open(L"notepad.exe");
	//process->showMemInfo(process->baseAddr + 0x1001);
	// process->showMemInfo(0x0000007BE72FF8E4);
	if (process->injectMM(L"test.dll")) dlog("Manual mapping: Success\n");
	// if (process->inject(L"test.dll")) dlog("Injecting: Success\n");
	
	process->close();
    return 0;
}

void dlog(const char* format, ...) {
#ifdef _DEBUG
	char buffer[512];
	va_list args;
	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	OutputDebugStringA(buffer);

	if (GetConsoleWindow()) {
		std::cout << buffer;
	}
#endif
}

std::string wstring_to_utf8(const wchar_t* data) {
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, data, -1, nullptr, 0, nullptr, nullptr);
	std::string result(size_needed - 1, 0); // exclude null terminator
	WideCharToMultiByte(CP_UTF8, 0, data, -1, &result[0], size_needed, nullptr, nullptr);
	return result;
}

std::string wstring_to_ansi(const wchar_t* data) {
	int size_needed = WideCharToMultiByte(CP_ACP, 0, data, -1, nullptr, 0, nullptr, nullptr);
	std::string result(size_needed - 1, 0); // exclude null terminator
	WideCharToMultiByte(CP_ACP, 0, data, -1, &result[0], size_needed, nullptr, nullptr);
	return result;
}
