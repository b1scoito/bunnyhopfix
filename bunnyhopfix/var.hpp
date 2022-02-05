#pragma once

namespace var
{
	namespace game {
#ifdef _WIN32
		// Windows
		inline std::wstring str_process = L"hl2.exe";
#else
		// Linux
		inline std::wstring str_process = L"hl2linux";
#endif
	}
}