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

#ifndef struct_h
#define struct_h

struct VacModule_t
{
    WORD m_nRunFuncExportFunctionOrdinal;
    WORD m_nRunFuncExportModuleOrdinal;
    DWORD m_pModuleBase;
    struct _IMAGE_NT_HEADERS* m_pNTHeaders;
    DWORD m_nImportedLibraryCount;
    DWORD m_pIAT;
};

enum VacModuleResult_t
{
    NOT_SET = 0x0,
    SUCCESS = 0x1,
    ALREADY_LOADED = 0x2,
    FAIL_TO_DECRYPT_VAC_MODULE = 0xb,
    FAIL_MODULE_SIZE_NULL = 0xc,
    UKN1 = 0xf,
    FAIL_GET_MODULE_TEMP_PATH = 0x13,
    FAIL_WRITE_MODULE = 0x15,
    FAIL_LOAD_MODULE = 0x16,
    FAIL_GET_EXPORT_RUNFUNC = 0x17,
    FAIL_GET_EXPORT_RUNFUNC_2 = 0x19
};

struct VacModuleCustomDosHeader_t
{
    struct _IMAGE_DOS_HEADER m_DosHeader;
    DWORD m_ValveHeaderMagic;
    DWORD m_nIsCrypted;
    DWORD m_nCryptedDataSize;
    DWORD unkn0;
    BYTE  m_CryptedRSASignature[0x80];
};

struct VacModuleInfo_t
{
    DWORD m_unCRC32;
    DWORD m_hModule;
    struct VacModule_t* m_pModule;
    DWORD m_pRunFunc;
    enum VacModuleResult_t m_nLastResult;
    DWORD m_nModuleSize;
    struct VacModuleCustomDosHeader_t* m_pRawModule;
    WORD unkn08;
    BYTE m_nUnknFlag_1;
    BYTE m_nUnknFlag_0;
    DWORD pCallableUnkn11;
    DWORD pCallableUnkn12;
    DWORD unkn13;
    DWORD unkn14;
    DWORD unkn15;
};

typedef bool(__fastcall* ExecVacModulePrototype)(void*, DWORD*, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, VacModuleResult_t*);
typedef struct VacModule_t*(__stdcall* AllocVacModulePrototype)(struct DOS_Header*, DWORD, char);
typedef bool(__stdcall* GetVacModuleEntrypointPrototype)(struct VacModuleInfo_t*, int);
typedef struct HINSTANCE__*(__stdcall* LoadModulePrototype)(LPCSTR, char, DWORD);
typedef HMODULE(__stdcall* LoadLibraryExWPrototype)(LPCWSTR, HANDLE, DWORD);
typedef struct VacModule_t* (__stdcall* UnloadVacModulePrototype)(struct VacModuleInfo_t*);

#endif // !struct_h
