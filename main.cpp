#include "process.h"

int main()
{
	PROCESS processObj;
	PPROCESS process = &processObj;
    return 0;
}

void dLog(const char* format, ...) {
#ifdef _DEBUG
	char buffer[512];
	char* args;
	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	OutputDebugStringA(buffer);
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
