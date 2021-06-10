/*

MIT License

Copyright (c) 2021 r0da [r0da@protonmail.ch]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include "context.h"

#include "security/obfu.hpp"

namespace context {

	HMODULE hSteamClient = NULL;

	DWORD pGetVacModuleEntrypoint = NULL;
	DWORD pUnloadVacModule = NULL;
	DWORD pExecVacModule = NULL;

	DWORD pOriginalExecVacModule = NULL;
	DWORD pOriginalGetVacModuleEntrypoint = NULL;

	void* hookGetVacModuleEntrypoint = NULL;

	// CRC are deferent in function of the STEAMID and HWID, So you have to define which module can be filtred.
	// 
	// NOTE : in fact, those values will be inserted in GetVacModuleEntrypointHook function
	// as I use virtualization, obfuscating values is useless but ...
	std::vector<DWORD> m_KnownCRC = {
		X(0x2B8DD987), X(0xCC29049A), X(0x53D9BA42),
		X(0x99499510), X(0xBF7B0E7D), X(0xEB9BDFAE),
		X(0xA3DE2639), X(0xC2B57235), X(0x0B5B0801),
		X(0xE26C6246), X(0x1DB20D9E), X(0x3DCF7ACF),
		X(0xC08DA5A2), X(0x09B02451), X(0xB8740B9D),
		X(0xC2DFDD81), X(0xD194CB8F), X(0x715BC840),
	};

	std::vector<DWORD> m_WhiteListedCRC = {
		X(0x2B8DD987), X(0xCC29049A), X(0x53D9BA42), X(0xD194CB8F), X(0x715BC840),
	};
}