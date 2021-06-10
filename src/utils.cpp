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

#include "utils.h"

#include <fstream>
#include <Windows.h>

#include "structs.h"

#include "security/obfu.hpp"
#include "security/xorstr.hpp"

bool DumpVacModule(void* pModule_) {

	VacModuleInfo_t* pModule = (VacModuleInfo_t*)pModule_;

	std::string logFileNAme = "C:\\Lumina\\vac.module.";

	char buffer[80];
	sprintf(buffer, ("%x"), pModule->m_unCRC32);

	logFileNAme += buffer;
	logFileNAme += ".dll";

	std::ifstream file(logFileNAme);

	if (!file.is_open()) {

		file.close();

		std::ofstream fout;
		fout.open(logFileNAme, std::ios::binary | std::ios::out);

		DWORD iAllocationSize = GetAllocationSize(pModule->m_pModule->m_pModuleBase);

		if (!iAllocationSize) {
			PF("[-] Fail to GetAllocationSize");
			return false;
		}

		// I alloc a new memory range because I modify the module in FixVacModule()
		DWORD pTmpModule = (DWORD)malloc(iAllocationSize);

		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)pModule->m_pModule->m_pModuleBase, (LPVOID)pTmpModule, iAllocationSize, NULL);

		FixVacModule(pTmpModule, (DWORD)pModule);

		fout.write((char*)pTmpModule, iAllocationSize);

		fout.close();

		PF(("[+] Module %p saved as : %s"), pModule->m_unCRC32, logFileNAme.c_str());

		return true;
	}
	else {
		PF(("[+] Module %p exists"), pModule->m_unCRC32);

	}
	return false;
}

void FixVacModule(DWORD pImage, DWORD pModule_) {

	VacModuleInfo_t* pModule = (VacModuleInfo_t*)pModule_;

	PIMAGE_NT_HEADERS32 pNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pImage + ((PIMAGE_DOS_HEADER)pImage)->e_lfanew);

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	PF(("[+] FixVacModule : Fixing PE"));

	for (size_t i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{
		DWORD iSectionNameSize = pSectionHeader->Name[0];
		DWORD iStart = pSectionHeader->Name[4];
		DWORD iSectionAlignment = pNtHeader->OptionalHeader.SectionAlignment;
		DWORD iSectionRva = pSectionHeader->Misc.VirtualSize - pModule->m_pModule->m_pModuleBase;

		pSectionHeader->PointerToRawData = iSectionRva;
		pSectionHeader->Misc.VirtualSize = pSectionHeader->SizeOfRawData;

		PF(("[+] : %p .%s\t(size : %x)"), i, &pSectionHeader->Name[1], pSectionHeader->PointerToRawData, pSectionHeader->Misc.VirtualSize);

		if (!strcmp((char*)&pSectionHeader->Name[0], ".text")) {

			PF(("[+] : EntryPoint fixed to %p"), pSectionHeader->PointerToRawData);

			pNtHeader->OptionalHeader.AddressOfEntryPoint = pSectionHeader->PointerToRawData;
		}
		
		pSectionHeader++;
	}
}

DWORD GetAllocationSize(DWORD iStartAddress) {

	MEMORY_BASIC_INFORMATION mbi;

	DWORD iOffset = iStartAddress;
	DWORD iSize = 0;
	DWORD iLastProtectionFlag = 0;

	do {
		if (!VirtualQuery((LPCVOID)iOffset, &mbi, sizeof(mbi)))
			break;

		if (mbi.State == MEM_RESERVE)
			break;

		/*
		if (iLastProtectionFlag == 0)
			iLastProtectionFlag = mbi.Protect;
		else if (mbi.Protect != iLastProtectionFlag)
			break;*/

		iSize += mbi.RegionSize;
		iOffset += mbi.RegionSize;

	} while (true);

	return iSize;
}

void ps(std::string message)
{
#ifdef _DEBUG

	VMProtectBeginUltra("ps");

	time_t rawtime;
	char buffer[80];
	char bufferLog[80];
	char printedString[150];

	time(&rawtime);

	strftime(buffer, sizeof(buffer), XorStr("%H:%M:%S"), localtime(&rawtime));

	strftime(bufferLog, sizeof(bufferLog), XorStr("%d.%m.%Y"), localtime(&rawtime));

	sprintf(printedString, XorStr("[%s] %s\r\n"), buffer, message.c_str());

	std::ofstream logFile;

	std::string logFileNAme = XorStr("C:\\Lumina\\vac.");

	logFileNAme += bufferLog;
	logFileNAme += XorStr(".txt");

	logFile.open(logFileNAme.c_str(), std::ios_base::app);

	std::string ff = printedString;

	logFile << ff.substr(0, ff.length() - 2);
	logFile << XorStr("\n");

	printf(printedString);

	VMProtectEnd();

#endif

}

void pf(std::string fmt, ...) {

#ifdef _DEBUG

	VMProtectBeginUltra("pf");

	int size = ((int)fmt.size()) * 2 + 50;
	std::string str;
	va_list ap;
	while (1) {
		str.resize(size);
		va_start(ap, fmt);
		int n = vsnprintf((char*)str.data(), size, fmt.c_str(), ap);
		va_end(ap);
		if (n > -1 && n < size) {
			str.resize(n);
			goto fine;
		}
		if (n > -1)
			size = n + 1;
		else
			size *= 2;
	}

fine:

	time_t rawtime;
	char buffer[80];
	char bufferLog[80];
	char printedString[150];

	time(&rawtime);

	strftime(buffer, sizeof(buffer), XorStr("%H:%M:%S"), localtime(&rawtime));

	strftime(bufferLog, sizeof(bufferLog), XorStr("%d.%m.%Y"), localtime(&rawtime));

	sprintf(printedString, XorStr("[%s] %s\r\n"), buffer, str.c_str());

	std::ofstream logFile;

	std::string logFileNAme = XorStr("C:\\Lumina\\vac.");

	logFileNAme += bufferLog;
	logFileNAme += XorStr(".txt");

	logFile.open(logFileNAme.c_str(), std::ios_base::app);

	std::string ff = printedString;

	logFile << ff.substr(0, ff.length() - 2);
	logFile << XorStr("\n");

	printf(printedString);

	VMProtectEnd();

#endif
}

std::vector<int> patternToByte(const char* pattern) {

	VMProtectBeginMutation("patternToByte");

	auto bytes = std::vector<int>{};

	auto start = const_cast<char*>(pattern);
	auto end = const_cast<char*>(pattern) + strlen(pattern);

	for (auto current = start; current < end; ++current) {
		if (*current == '?') {
			++current;
			if (*current == '?')
				++current;
			bytes.push_back(-1);
		}
		else {
			bytes.push_back(strtoul(current, &current, 16));
		}
	}

	VMProtectEnd();

	return bytes;
}

std::uint8_t* patternScan(void* module, const char* signature) {

	VMProtectBeginMutation("patternScan");

	auto dos_headers = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
	auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>((std::uint8_t*)module + dos_headers->e_lfanew);

	auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;
	auto pattern_bytes = patternToByte(signature);
	auto scan_bytes = reinterpret_cast<std::uint8_t*>(module);

	auto s = pattern_bytes.size();
	auto d = pattern_bytes.data();

	for (auto i = 0ul; i < size_of_image - s; ++i) {
		bool found = true;
		for (auto j = 0ul; j < s; ++j) {
			if (scan_bytes[i + j] != d[j] && d[j] != -1) {
				found = false;
				break;
			}
		}
		if (found) {
			return &scan_bytes[i];
		}
	}

	VMProtectEnd();

	return nullptr;
}