#include "stdafx.h"

void dlog(const char* format, ...) {
	char buffer[512];
	va_list args;
	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

#ifdef _DEBUG
	OutputDebugStringA(buffer);
#endif

	if (GetConsoleWindow()) {
		std::cout << buffer;
	}
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
