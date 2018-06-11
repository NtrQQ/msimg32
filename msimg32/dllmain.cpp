// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

void LoadSysDll();

HMODULE g_hModule;
TCHAR szDLL[MAX_PATH + 1] = { 0 };
INT g_Tmp1 = GetSystemDirectory(szDLL, MAX_PATH);
//PathAppend(szDLL, L"\\msimg32.dll");
HINSTANCE hDll = LoadLibrary(lstrcat(szDLL, L"\\msimg32.dll"));

// 宏简化代码量
#define MAKE_STUB_FUNC(FUNC_NO,FUNC_NAME) __pragma(comment(linker, "/EXPORT:" #FUNC_NAME "=__" #FUNC_NAME ",@" #FUNC_NO ))\
FARPROC g_pfnFunPtr##FUNC_NO = GetProcAddress(hDll, #FUNC_NAME); \
extern "C" void __declspec(naked) _##FUNC_NAME ()\
{ \
	__asm jmp [g_pfnFunPtr##FUNC_NO] \
}


// 实现5个跳板函数
MAKE_STUB_FUNC(1, vSetDdrawflag)
MAKE_STUB_FUNC(2, AlphaBlend)
MAKE_STUB_FUNC(3, DllInitialize)
MAKE_STUB_FUNC(4, GradientFill)
MAKE_STUB_FUNC(5, TransparentBlt)

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	g_hModule = hModule;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		LoadSysDll();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

