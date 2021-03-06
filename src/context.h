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

#ifndef context_h

#define context_h

#include <Windows.h>
#include <vector>

namespace context {

	extern HMODULE hSteamClient;

	extern DWORD pGetVacModuleEntrypoint;
	extern DWORD pUnloadVacModule;
	extern DWORD pExecVacModule;

	extern DWORD pOriginalExecVacModule;
	extern DWORD pOriginalGetVacModuleEntrypoint;

	extern void* hookGetVacModuleEntrypoint;

	extern std::vector<DWORD> m_KnownCRC;
	extern std::vector<DWORD> m_WhiteListedCRC;
}

#endif // !context_h