// by Lance.Moe
// 2017.02.15

#pragma once

#include "DisassembleProlog.h"

#pragma pack(push,1) //保证按照1字节对齐
struct FILL_CODE
{
	BYTE byPushCode;
	LPBYTE lpAddress;
	BYTE byRetnCode;
}PUSH_CODE;
#pragma pack(pop)

class CHookEngine
{
private:
	LPBYTE m_pOldCode;
	LPBYTE m_pSaveHook;
	int m_nNowLen;

	int VAtoFileOffset(LPVOID lpModuleBase, LPVOID lpVA);
	void WritePUSH_RET(LPVOID lpTargetProc, LPVOID lpNewProc);
	void WriteNOP(LPVOID lpTargetProc, int nLength);
	bool AntiHook(LPVOID lpTargetProc, int nLength, LPVOID lpBak);
	int GetPatchLength(LPVOID lpFuncStart, LPBYTE lpbThunk);
	int GetPatchLength(LPVOID lpFuncStart, LPBYTE lpbThunk, int nMaxLength);
public:
	CHookEngine();
	LPVOID InstallHook(LPVOID lpTargetProc, LPVOID lpNewProc);
	LPVOID GetOldCode();
	void Uninstallhook();
};

int CHookEngine::VAtoFileOffset(LPVOID lpModuleBase, LPVOID lpVA)
{
	return (DWORD)lpVA - (DWORD)lpModuleBase;
}
void CHookEngine::WritePUSH_RET(LPVOID lpTargetProc, LPVOID lpNewProc)
{
	// 写入一个 68 XXXXXXXX C3
	PUSH_CODE.lpAddress = (LPBYTE)lpNewProc;
	//memcpy((LPVOID)TargetProc, &PUSH_CODE, sizeof(PUSH_CODE));
	WriteProcessMemory((LPVOID)-1, lpTargetProc, &PUSH_CODE, sizeof(PUSH_CODE), nullptr);
}
void CHookEngine::WriteNOP(LPVOID lpTargetProc, int nLength)
{
	// 填充NOP，方便反汇编观察
	static BYTE NOP[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
	WriteProcessMemory((LPVOID)-1, lpTargetProc, &NOP, nLength, nullptr);
	//memset((LPVOID)TargetProc,0x90,len);
}

bool CHookEngine::AntiHook(LPVOID lpTargetProc, int nLength, LPVOID lpBak)
{
	WCHAR wszStack[MAX_PATH + 1];
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(lpTargetProc, &mbi, sizeof(mbi));
	GetModuleFileName((HMODULE)mbi.AllocationBase, wszStack, MAX_PATH);

	HMODULE hModule = GetModuleHandle(wszStack);

	int nOffset = VAtoFileOffset(hModule, lpTargetProc);

	HANDLE hFile = CreateFile(wszStack, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		HANDLE hFileMap = CreateFileMapping(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
		CloseHandle(hFile);

		LPBYTE lpBuf = (LPBYTE)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
		CloseHandle(hFileMap);

		memcpy(lpBak, lpBuf + nOffset, nLength);
		UnmapViewOfFile(lpBuf);

		return true;
	}
	return false;
}

int CHookEngine::GetPatchLength(LPVOID lpFuncStart, LPBYTE lpbThunk, int nMaxLength)
{
	BYTE abyTemp[100];
	if (!AntiHook(lpFuncStart, 100, abyTemp)) return 0;

	int nActualOpLength = DisassembleProlog(abyTemp, nMaxLength);

	if (nActualOpLength == 0) return 0;

	//*(BYTE*)thunk = actual_oplen;

	lpbThunk++;
	memcpy(lpbThunk, abyTemp, nActualOpLength);

	nActualOpLength += (nMaxLength + 1);

	return nActualOpLength;
}

int CHookEngine::GetPatchLength(LPVOID lpFuncStart, LPBYTE lpbThunk)
{
	return GetPatchLength(lpFuncStart, lpbThunk, 6);
}

CHookEngine::CHookEngine()
{
	// 初始化
	PUSH_CODE.byPushCode = 0x68;
	PUSH_CODE.byRetnCode = 0xC3;

	m_nNowLen = 0;
	m_pSaveHook = (LPBYTE)VirtualAlloc(nullptr, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//备份长度、备份指令、JMP指令
}

LPVOID CHookEngine::InstallHook(LPVOID lpTargetProc, LPVOID lpNewProc)
{
	// 检查传入参数
	if (lpTargetProc == nullptr || lpNewProc == nullptr) return nullptr;

	// 保存指令
	LPBYTE lpbPtr = m_pSaveHook + m_nNowLen;

	// 获得需要处理的长度
	int nThunkLen = GetPatchLength(lpTargetProc, lpbPtr, sizeof(PUSH_CODE));
	if (nThunkLen == 0) return nullptr;

	m_nNowLen += nThunkLen;
	if (m_nNowLen > 1024) return nullptr;

	// 调到原始地址接着运行
	WritePUSH_RET(lpbPtr + nThunkLen - sizeof(PUSH_CODE), LPBYTE(lpTargetProc) + nThunkLen - sizeof(PUSH_CODE) - 1);

	// 写入跳转到新程序
	WritePUSH_RET(lpTargetProc, lpNewProc);

	//对 多余字节填充NOP
	if (nThunkLen > 13) WriteNOP(LPBYTE(lpTargetProc) + 6, nThunkLen - 13);

	*lpbPtr = nThunkLen;
	lpbPtr++;
	m_pOldCode = lpbPtr;
	return lpbPtr;
}

LPVOID CHookEngine::GetOldCode()
{
	return m_pOldCode;
}

void CHookEngine::Uninstallhook()
{
	if (m_pOldCode == 0) return;

	LPBYTE lpbPtr = m_pOldCode - 1;
	int nMinLen = *lpbPtr;

	LPBYTE lpBase = LPBYTE(*LPDWORD(lpbPtr + nMinLen - 5) - (nMinLen - 7));// + 5 + (DWORD)ptr;
	//DbgPrint(L"%X %X",base,(DWORD)ptr);//[776] 7785C43A 6726E1

	//memcpy((LPVOID)base, (LPVOID)(ptr + 1), nMinLen - 7);
	WriteProcessMemory((LPVOID)-1, lpBase, lpbPtr + 1, nMinLen - 7, nullptr);

	//WriteProcessMemory((LPVOID)-1,(LPVOID)base, ptr, nMinLen, nullptr);
	memset(lpbPtr, 0xC3, nMinLen);
	//free();
}

//安装虚函数hook
LPVOID VirtualHook_(DWORD dwVbtlNo, LPVOID lpClass, LPVOID lpNewAddr)
{
	LPDWORD lpOldAddr = LPDWORD(*LPDWORD(lpClass)) + dwVbtlNo;

	DWORD dwOldProtect = 0;
	if (::VirtualProtect(lpOldAddr, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		DWORD dwAddr = *lpOldAddr;
		*lpOldAddr = (DWORD)lpNewAddr;
		::VirtualProtect(lpOldAddr, sizeof(DWORD), dwOldProtect, 0);
		return (void*)dwAddr;
	}

	return (new CHookEngine)->InstallHook((LPVOID)*lpOldAddr, lpNewAddr);
	//return InstallHook(*oldAddr, newAddr);

}