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

#include <Windows.h>
#include <iostream>
#include <shared_mutex>
#include <filesystem>

#include "structs.h"
#include "context.h"
#include "utils.h"
#include "hooks.h"

#include "minhook/include/MinHook.h"

#include "security/lazy.hpp"
#include "security/xorstr.hpp"
#include "security/obfu.hpp"

using namespace context;

bool initSignatures() {

	VMProtectBeginUltra("initSignatures");

	pGetVacModuleEntrypoint = (DWORD)patternScan(hSteamClient, XorStr("55 8B EC 83 EC 28 53 56 8B 75 08 8B"));

	if (pGetVacModuleEntrypoint == NULL) {
#ifdef _DEBUG
		PF(("[-] pGetVacModuleEntrypoint == NULL"));
#endif
		return false;
	}
#ifdef _DEBUG
	PF(("[+] pGetVacModuleEntrypoint 0x%p"), pGetVacModuleEntrypoint);
#endif

	pExecVacModule = (DWORD)patternScan(hSteamClient,    XorStr("55 8B EC 6A FF 68 ? ? ? ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 64 89 25"));

	if (pExecVacModule == NULL) {
#ifdef _DEBUG
		PF(("[-] pExecVacModule == NULL"));
#endif
		return false;
	}
#ifdef _DEBUG
	PF(("[+] pExecVacModule 0x%p"), pExecVacModule);
#endif

	pUnloadVacModule = (DWORD)patternScan(hSteamClient, XorStr("55 8B EC 81 EC 04 01 00 00 53 56 8B 75"));

	if (pUnloadVacModule == NULL) {
#ifdef _DEBUG
		PF(("[-] pUnloadVacModule == NULL"));
#endif
		return false;
	}
#ifdef _DEBUG
	PF(("[+] pUnloadVacModule 0x%p"), pUnloadVacModule);
#endif

	VMProtectEnd();

	return true;
}

bool hook(DWORD original, DWORD hook, DWORD callback) {

	VMProtectBeginUltra("initSignatures");

	if (MH_CreateHook((LPVOID)original, (LPVOID)hook, reinterpret_cast<LPVOID*>(callback)) != MH_OK)
	{
#ifdef _DEBUG
		PF(("[-] MH_CreateHook() != MH_OK"));
#endif 
		return false;
	}

	if (MH_EnableHook((LPVOID)original) != MH_OK)
	{
#ifdef _DEBUG
		PF(("[-] MH_EnableHook() != MH_OK"));
#endif 
		return false;
	}

	VMProtectEnd();

	return true;
}

bool initHook() {
	
	VMProtectBeginUltra("initHook");

	if (MH_Initialize() != MH_OK)
	{
#ifdef _DEBUG
		PF(("[-] MH_Initialize() != MH_OK"));
#endif 
		return false;
	}

	if (!hook(pExecVacModule, (DWORD)ExecVacModuleHook, (DWORD)&pOriginalExecVacModule)) {
#ifdef _DEBUG
		PF(("[-] Fail to hook ExecVacModule"));
#endif 
		return false;
	}
#ifdef _DEBUG
	PF(("[+] ExecVacModule Hooked !"));
#endif 

	if (!hook(pGetVacModuleEntrypoint, (DWORD)GetVacModuleEntrypointHook, (DWORD)&pOriginalGetVacModuleEntrypoint)) {
#ifdef _DEBUG
		PF(("[-] Fail to hook GetVacModuleEntrypoint"));
#endif 
		return false;
	}
#ifdef _DEBUG
	PF(("[+] GetVacModuleEntrypoint Hooked !"));
#endif 

	VMProtectEnd();

	return true;
}

void init() {

	VMProtectBeginUltra("init");

	hSteamClient = GetModuleHandle("steamservice.dll");//(HMODULE)LI_MODULE("steamservice.dll").cached();

	if (hSteamClient == NULL) {

#ifdef _DEBUG
		PF(("[-] hSteamClient == NULL"));
#endif 
		return;
	}

#ifdef _DEBUG
	PF(("[+] hSteamClient 0x%p"), hSteamClient);
#endif 

	if (!initSignatures()) {
#ifdef _DEBUG
		PF(("[-] Fail to init signatures"));
#endif 
		return;
	}

	if (!initHook()) {
#ifdef _DEBUG
		PF(("[-] Fail to init hooks"));
#endif 
		return;
	}

	VMProtectEnd();
}


DWORD WINAPI Start(LPVOID param) {

	VMProtectBeginUltra("Start");

#ifdef _DEBUG
	AllocConsole();

	freopen_s((FILE**)stdout, XorStr("CONOUT$"), XorStr("w"), stdout);

	PF(("Lumina VAC Module Filter by r0da"));
#endif

	while (!(GetModuleHandleA)(XorStr("steamservice.dll")))
		Sleep(125);

	init();

	while (true)
		Sleep(125);

	VMProtectEnd();

	return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {

	VMProtectBeginUltra("DllMain");

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls((HMODULE)hinstDLL);

		HANDLE thread = CreateThread(0, 0, Start, hinstDLL, 0, 0);

		CloseHandle(thread);
	}

	VMProtectEnd();

	return TRUE;
}