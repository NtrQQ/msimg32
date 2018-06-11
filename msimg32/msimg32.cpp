// msimg32.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "HookEngine.h"

typedef int(_stdcall *_MoveFile)(WCHAR *, WCHAR *);

CHookEngine g_hookMoveFile;
_MoveFile MoveFile_ = nullptr;

long _stdcall new_MoveFile(WCHAR *pszExistingFileName, WCHAR *pszNewFileName)
{
	long lResult = 0;
	if (wcsstr(pszExistingFileName, L"msimg32.dll") == NULL)
		lResult = MoveFile_(pszExistingFileName, pszNewFileName);
	return lResult;
}

void LoadSysDll()
{
	MoveFile_ = (_MoveFile)g_hookMoveFile.InstallHook(GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "MoveFileW"), &new_MoveFile);

	// 写入注入代码
	LoadLibrary(L"NtrQQ\\NtrQQ.dll");
}