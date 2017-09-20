#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include "tlhelp32.h"
#include "winternl.h"//for using NtQueryInformationProcess

bool IsHook(DWORD  pFuncAddr)
bool FD_IsDebuggerPresent()
bool FD_PEB_BeingDebuggedFlag()
bool FD_PEB_NtGlobalFlags()
bool FD_Heap_HeapFlags()
bool FD_Heap_ForceFlags()
bool FD_Heap_Tail()
bool FD_CheckRemoteDebuggerPresent()
bool FD_NtQueryInfoProc_DbgPort()
bool FD_NtQueryInfoProc_DbgObjHandle()
bool FD_NtQueryInfoProc_DbgFlags()
bool FD_SeDebugPrivilege()
bool FD_Parent_Process()
bool FD_DebugObject_NtQueryObject()


typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
	UNICODE_STRING TypeName;
	ULONG Reserved [22];    // reserved for internal use
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;


//从dll获取funcaddr
DWORD GetFuncAddr(const char* sDllName,const char* sFuncName)
{
	DWORD  pFuncAddr;
	HMODULE hDllLib = LoadLibrary(_T(sDllName));
	if (INVALID_HANDLE_VALUE==hDllLib)
	{
		return;
	} 
	(DWORD&)pFuncAddr = GetProcAddress(hDllLib,_T(sFuncName));
	if (NULL==pFuncAddr)
	{
		return;
	}
	return pFuncAddr;
}
DWORD GetProcessIDByName(char *pProcessName) 
{ 
	 PROCESSENTRY32 processinfo; 
	 processinfo.dwSize = sizeof(processinfo); 
	 HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); 
	 if(hSnapshot == NULL)
		 return false;
	 if (!Process32First(hSnapshot, &processinfo))
		 return false;
	 while (Process32Next(hSnapshot,&processinfo))
	 {
		 if(_stricmp(pProcessName,processinfo.szExeFile)==0)
			 return processinfo.th32ProcessID; 
	 } 
	 return false; 
}
char* GetProcessNameById(DWORD dwPid)
{
	char* pProcessName;
	PROCESSENTRY32 processinfo;
	processinfo.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hSnapshot == NULL)
		return false;
	if (!Process32First(hSnapshot, &processinfo))
		return false;
	while (Process32Next(hSnapshot, &processinfo)) 
	{
		if (processinfo.th32ProcessID == dwPid) 
		{
			strcpy(pProcessName, processinfo.szExeFile);
			return pProcessName;
		}
	}
	return false;
}
DWORD GetParentProcessID(DWORD dwPID)
{
	HANDLE hMyProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION,false,dwPID);
	PROCESS_BASIC_INFORMATION ProcessBasicInformation;
	LONG status = NtQueryInformationProcess(hMyProcessHandle,NULL,(PVOID)&ProcessBasicInformation,sizeof(PROCESS_BASIC_INFORMATION),NULL);
	//if status
	DWORD dwParentPID = (DWORD&)ProcessBasicInformation.Reserved3;
	CloseHandle(hMyProcessHandle);
	return dwParentPID;
}
//检查是否被挂钩
bool IsHook(DWORD  pFuncAddr)
{
	//check softbreak
	if(*(BYTE*)pFuncaddr==0xcc)
	{
		return true;
	}
	//check hook
	if(*(BYTE*)pFuncAddr!=0x64)
	{
		return true;
	}
	return false;
}
bool FD_IsDebuggerPresent()
{
	BOOL WINAPI *(pIsDebuggerPresent)(void);
	//HMODULE hDllLib = LoadLibrary(_T("kernel32.dll"));
	DWORD  pFuncAddr = GetFuncAddr("kernel32.dll","IsDebuggerPresent")
	if (NULL==pFuncAddr)
	{
		return;
	} 
	else
	{
		if(IsHook(pFuncAddr))
		{
			return true;
		}
		pIsDebuggerPresent = pFuncAddr;
		if((*pIsDebuggerPresent)())
		{
			return true;
		}
		else
		{
			return false;
		}
	}
}
}
bool FD_PEB_BeingDebuggedFlag()
{
	__asm
	{
		//EAX=TEB.ProcessEnvironmentBlock
		mov eax, fs:[30h] 
		inc eax
		inc eax
		mov eax, [eax]
		//AL=PEB.BeingDebugged
		and eax,0x000000ff
		test eax, eax
		jne rt_label
	}
	return false;
rt_label:
	return true;
}
bool FD_PEB_NtGlobalFlags()
{
	__asm
	{
		//EAX=TEB.ProcessEnvironmentBlock
		mov eax, fs:[30h]
		//EAX=PEB.NtGlobalFlags
		mov eax, [eax+68h]
		and eax, 0x70
		test eax, eax
		jne rt_label
	}
	return false;
rt_label:
	return true;
}
bool FD_Heap_HeapFlags()//The same as function: kernel32_GetProcessHeap()
{
	__asm
	{
		//EAX=TEB.ProcessEnvironmentBlock
		mov eax, fs:[30h]
		//EAX=PEB.ProcessHeap
		mov eax, [eax+18h]
		//EAX=PEB.ProcessHeap.Flags
		mov eax, [eax+0ch]
		cmp eax, 2
		jne rt_label
	}
	return false;
rt_label:
	return true;
}
bool FD_Heap_ForceFlags()
{
	__asm
	{
		//EAX=TEB.ProcessEnvironmentBlock
		mov eax, fs:[30h]
		//EAX=PEB.ProcessHeap
		mov eax, [eax+18h]
		//EAX=PEB.ProcessHeap.ForceFlags
		mov eax, [eax+10h]
		test eax, eax
		jne rt_label
	}
	return false;
rt_label:
	return true;
}
bool FD_Heap_Tail()
{
	__asm
	{
		mov eax, buff
		//get unused_bytes
		movzx ecx, byte ptr [eax-2]
		//size
		movzx edx, word ptr [eax-8]
		sub eax, ecx
		lea edi, [edx*8+eax]
		mov al, 0abh
		mov cl, 8
		repe scasb
		je rt_label
	}
	return false;
rt_label:
	return true;
}
bool FD_CheckRemoteDebuggerPresent() 
{ 
	DWORD pFuncAddr = GetFuncAddr("kernel32.dll","CheckRemoteDebuggerPresent") 
	if (NULL==pFuncAddr) 
		return;
	else
	{ 
		__asm 
			{ 
			push eax
			push esp
			//hProcess 
			push 0xffffffff
			call pFuncAddr
			//error？
			test eax,eax
			//error! 
			je rf_label
			//no error 
			pop eax
			test eax,eax 
			je rf_label
			} 
		return true; 
rf_label: 
		return false; 
	} 
}
bool FD_NtQueryInfoProc_DbgPort() 
{ 
	DWORD pFuncAddr = GetFuncAddr("ntdll.dll","ZWQueryInformationProcess")
	if (NULL==pFuncAddr)
		return;
	else
	{ 
		__asm{ 
				push 0
				//ProcessInformationLength 
				push 4
				//ProcessInformation
				push eax 
				push esp 
				//ProcessDebugPort 
				push 7
				//ProcessHandle 
				push 0xffffffff
				call pFuncAddr 
				//error?
				test eax,eax; 
				//error! 
				je rf_label; 
				//no error 
				pop eax; 
				test eax,eax 
				je rf_label; 
			} 
		return true;//is debugging
rf_label: 
		return false; 
	} 
}
//2.9
bool FD_NtQueryInfoProc_DbgObjHandle()
{
	DWORD pFuncAddr = GetFuncAddr("ntdll.dll","ZWQueryInformationProcess")
	if (NULL==pFuncAddr)
		return;
	else
	{ 
		__asm{ 
			push 0
			//ProcessInformationLength 
			push 4
			//ProcessInformation
			push eax 
			push esp 
			//ProcessDebugObjectHandle 
			push 0x0000001e
			//ProcessHandle 
			push 0xffffffff
			call pFuncAddr 
			//error?
			test eax,eax; 
			//error! 
			je rf_label; 
			//no error 
			pop eax; 
			test eax,eax 
			je rf_label; 
		} 
		return true;//is debugging
rf_label: 
		return false; 
	} 
}
bool FD_NtQueryInfoProc_DbgFlags()
{
	DWORD pFuncAddr = GetFuncAddr("ntdll.dll","ZWQueryInformationProcess")
	if (NULL==pFuncAddr)
		return;
	else
	{ 
		__asm{ 
			push 0
			//ProcessInformationLength 
			push 4
			//ProcessInformation
			push eax 
			push esp 
			//ProcessDebugFlags 
			push 0x0000001f
			//ProcessHandle 
			push 0xffffffff
			call pFuncAddr 
			//error?
			test eax,eax; 
			//error! 
			je rf_label; 
			//no error 
			pop eax; 
			test eax,eax 
			je rf_label; 
		} 
		return true;//is debugging
rf_label: 
		return false; 
	} 
}
bool FD_SeDebugPrivilege()
{
	char *pProcessName ="csrss.exe";
	DWORD dwCsrssPid = GetProcessIDByName(char *pProcessName);
	HANDLE hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS,false,dwCsrssPid);
	if(NULL!=hProcessHandle)
	{
		CloseHandle(hProcessHandle);
		return true;
	}
	return false;
}
bool FD_Parent_Process()
{
	//DWORD pFuncAddr = GetFuncAddr("kernel32","GetCurrentProcessID");
	DWORD dwMyProcessId = GetCurrentProcessId();
	DWORD dwParentProcessId = GetParentProcessID(dwMyProcessId);
	const char* lpParentProcessName = GetProcessNameById(dwParentProcessId);
	CHAR *pProcessName = "explorer.exe";
	if(_stricmp(pProcessName,lpParentProcessName))
	{
		return true;
	}
	return false;
}
bool FD_DebugObject_NtQueryObject()
{
	DWORD pFuncName = GetFuncAddr("ntdll.dll","ZwQueryObject");
	if(pFuncName==NULL)
		return false;
	unsigned char szdbgobj[25]=
		"\x44\x00\x65\x00\x62\x00\x75\x00\x67\x00\x4f\x00\x62\x00\x6a\x00\x65\x00\x63\x00\x74\x00\x00\x00";
	unsigned char *psz=&szdbgobj[0];
	__asm
	{
		xor    ebx,ebx
		push   ebx
		push   esp
		push   ebx
		push   ebx
		push   3
		push   ebx
		Call   dword ptr [pFuncName]
		pop    edi
		push   4
		push   1000h
		push   edi
		push   ebx
		call   dword ptr [VirtualAlloc]
		push   ebx
		push   edi
		push   eax
		push   3
		push   ebx
		xchg   esi,eax
		Call   dword ptr [pFuncName]
		lodsd
		xchg   ecx,eax
lable1: lodsd
		movzx  edx,ax
		lodsd
		xchg   esi,eax
		cmp    edx,16h
		jne    label2
		xchg   ecx,edx
		mov    edi,psz
		repe   cmpsb
		xchg   ecx,edx
		jne    label2
		cmp    dword ptr [eax],edx
		jne    rt_label
lable2: add    esi,edx
		and    esi,-4
		lodsd
		loop   label1
	}
	return false
rt_label:
	return true
}
