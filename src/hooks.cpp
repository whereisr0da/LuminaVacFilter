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

#include "structs.h"
#include "hooks.h"
#include "context.h"
#include "utils.h"

#include "security/xorstr.hpp"
#include "security/obfu.hpp"

using namespace context;

bool __stdcall GetVacModuleEntrypointHook(struct VacModuleInfo_t* pModule, int iFlags) {

	VMProtectBeginUltra("GetVacModuleEntrypointHook");

	// call the original 
	bool bOriginalReturn = ((GetVacModuleEntrypointPrototype)pOriginalGetVacModuleEntrypoint)(pModule, iFlags);

#ifdef _DEBUG
	PF("--------------------------------------");
	PF("[+] GetVacModuleEntrypointHook : start");
	PF("[+] : iFlags\t%d", iFlags);
	PF("[+] : m_unCRC32\t%p", pModule->m_unCRC32);
	PF("[+] : m_pRunFunc\t%p", pModule->m_pRunFunc);
	PF("[+] : m_nModuleSize\t%p", pModule->m_nModuleSize);
	PF("[+] : m_pRawModule\t%p", pModule->m_pRawModule);
	PF("[+] : m_nLastResult\t%d", pModule->m_nLastResult);
	PF("[+] : m_nUnknFlag_0\t%d", pModule->m_nUnknFlag_0);
	PF("[+] : m_nUnknFlag_1\t%d", pModule->m_nUnknFlag_1);
	PF("[+] : m_pModule->m_pIAT\t%p", pModule->m_pModule->m_pIAT);
	PF("[+] : m_pNTHeaders->m_pOldIAT\t%p", pModule->m_pModule->m_pNTHeaders->OptionalHeader.DataDirectory[13].VirtualAddress);
	PF("[+] : m_pModule->m_pModuleBase\t%p", pModule->m_pModule->m_pModuleBase);
	PF("[+] : m_pModule->m_pNTHeaders\t%p", pModule->m_pModule->m_pNTHeaders);
	PF("[+] : m_pModule->m_nImportedLibraryCount\t%p", pModule->m_pModule->m_nImportedLibraryCount);
	PF("[+] : m_pModule->m_nRunFuncExportFunctionOrdinal\t%p", pModule->m_pModule->m_nRunFuncExportFunctionOrdinal);
	PF("[+] : m_pModule->m_nRunFuncExportModuleOrdinal\t%p", pModule->m_pModule->m_nRunFuncExportModuleOrdinal);
#endif 
	
	if (pModule->m_unCRC32) {

		bool bFound = false;

		for (DWORD iCrc : m_KnownCRC) {

			if (X(pModule->m_unCRC32) == iCrc) {
#ifdef _DEBUG
				PF("[+] GetVacModuleEntrypointHook : known module %p", pModule->m_unCRC32);
#endif 
				bFound = true;
				break;
			}
		}

		// dump it
		DumpVacModule(pModule);

		if (!bFound) {
#ifdef _DEBUG
			PF("[-] GetVacModuleEntrypointHook : unknown module %p", pModule->m_unCRC32);
#endif 
		}
		else {
			// check that this module is not whitelisted
			for (DWORD iCrc : m_WhiteListedCRC) {

				// it's a needed module
				if (X(pModule->m_unCRC32) == iCrc) {
#ifdef _DEBUG
					PF("[+] GetVacModuleEntrypointHook : whitelisted module %p", pModule->m_unCRC32);
#endif 
					return bOriginalReturn;
				}
			}
		}
	}

	if (pModule->m_pRunFunc) {

		// null _runfunc@20
		pModule->m_pRunFunc = NULL;

#ifdef _DEBUG
		PF("[+] GetVacModuleEntrypointHook : m_pRunFunc reset");
#endif 
	}

	// unload the module
	((UnloadVacModulePrototype)pUnloadVacModule)(pModule);

#ifdef _DEBUG
	PF("[+] GetVacModuleEntrypointHook : %p unloaded", pModule->m_unCRC32);
#endif 

	// patch the result 
	pModule->m_nLastResult = SUCCESS;
	
	VMProtectEnd();

	return bOriginalReturn;
}

bool __fastcall ExecVacModuleHook(void* arg1, DWORD* arg2, DWORD arg3, DWORD arg4, DWORD arg5, DWORD arg6, DWORD arg7, DWORD arg8, DWORD arg9, VacModuleResult_t* pModuleStatus) {

	VMProtectBeginUltra("ExecVacModuleHook");

#ifdef _DEBUG
	PF(("[+] ExecVacModuleHook : start"));
#endif 

	((ExecVacModulePrototype)pOriginalExecVacModule)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, pModuleStatus);

	if (*pModuleStatus != SUCCESS || *pModuleStatus != ALREADY_LOADED) {
		*pModuleStatus = SUCCESS;

#ifdef _DEBUG
		PF("[+] ExecVacModuleHook : *pModuleStatus = SUCCESS");
#endif 
	}

	VMProtectEnd();

	return SUCCESS;
}
