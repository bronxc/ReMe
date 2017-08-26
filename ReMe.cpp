#include "stdafx.h"
#include <windows.h>
#include "tlhelp32.h"
#include "winternl.h"
#include <winnt.h>


#define EXCEPTION_EXECUTE_HANDLER 1
#define ProcessBasicInformation 0  
  
typedef LONG (WINAPI *PROCNTQSIP)(
	HANDLE processHandle,
	UINT processInformationClass,
	PVOID processInformation,
	ULONG processInformationLength,
	PULONG returnLength);

bool Debugger(void);
bool IsHook(DWORD  pFuncAddr);
DWORD GetParentProcessID(DWORD dwPID);
char* GetProcessNameById(DWORD dwPid);
DWORD GetProcessIDByName(char *pProcessName);
FARPROC  GetFuncAddr(const char* sDllName,const char* sFuncName);
bool FD_IsDebuggerPresent(void);
bool FD_PEB_BeingDebuggedFlag(void);
bool FD_NtQueryInfoProc_DbgPort(void);
bool FD_SeDebugPrivilege(void);
bool FD_Parent_Process(void);
bool FD_NtQueryInfoProc_DbgFlags(void);


#pragma comment(linker,"/INCLUDE:__tls_used")

void NTAPI tls_callback1(LPVOID dllhhanle,DWORD reason,PVOID Reserved)
{
	if(FD_SeDebugPrivilege())
	{
		//printf("FD_IsDebuggerPresent:ture");
		exit(0);
	}
}


void NTAPI tls_callback2(LPVOID dllhhanle,DWORD reason,PVOID Reserved)
{
	if (FD_PEB_BeingDebuggedFlag())
	{
		//printf("FD_PEB_BeingDebuggedFlag:ture");
		exit(0);
	}
}


#pragma  data_seg(".CRT$XLX")
PIMAGE_TLS_CALLBACK pTLS_CALLBACKs[]={tls_callback1,tls_callback2,0}; //end with 0
#pragma  data_seg()



bool IsHook(FARPROC   pFuncAddr)
{
	FARPROC   pFuncAddrtmp = pFuncAddr;
	//check softbreak
	if(*(BYTE*)pFuncAddrtmp==0xcc)
	{
		return true;
	}
	//check hook
	if(*(BYTE*)pFuncAddrtmp!=0x64)
	{
		return true;
	}
	return false;
}

FARPROC  GetFuncAddr(const char* sDllName,const char* sFuncName)
{
	FARPROC   pFuncAddr;
	HMODULE hDllLib = LoadLibrary(sDllName);
	if (INVALID_HANDLE_VALUE==hDllLib)
	{
		return NULL;
	} 
	pFuncAddr =GetProcAddress(hDllLib,sFuncName);
	if (NULL==pFuncAddr)
	{
		return NULL;
	}
	return pFuncAddr;
}
PROCNTQSIP GetNTQIPAddr()
{
	PROCNTQSIP NtQueryInformationProcess;  
	NtQueryInformationProcess = (PROCNTQSIP)GetProcAddress(  
                                            GetModuleHandle("ntdll"),  
                                            "NtQueryInformationProcess"  
                                            );  
  
    if (!NtQueryInformationProcess)  
       return 0;
	return NtQueryInformationProcess;
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
	DWORD dwParentPID = (DWORD)-1;  
	HANDLE hMyProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION,false,dwPID);
	if(!hMyProcessHandle)
		return (DWORD)-1;
	PROCESS_BASIC_INFORMATION PBI;
	PROCNTQSIP NtQueryInformationProcess = GetNTQIPAddr();
	//printf("%x\n",NtQueryInformationProcess);
	LONG status = NtQueryInformationProcess(hMyProcessHandle,ProcessBasicInformation,(PVOID)&PBI,sizeof(PROCESS_BASIC_INFORMATION),NULL);
	if(!status)
		dwParentPID = (DWORD&)PBI.Reserved3;
	//printf("%x\n",dwParentPID);
	CloseHandle(hMyProcessHandle);
	return dwParentPID;
}

bool FD_IsDebuggerPresent()
{

	//HMODULE hDllLib = LoadLibrary(_T("kernel32.dll"));
	//FARPROC   pFuncAddr = GetFuncAddr("kernel32.dll","IsDebuggerPresent");
	//printf("IsDebuggerPresent_addr:%x",pFuncAddr);
	//if (NULL==pFuncAddr)
	{
		//return false;
	} 
	//else
	{
		//if(IsHook(pFuncAddr))
		{
			//return true;
			//printf("IsHook:ture");
		}
		//pIsDebuggerPresent=pFuncAddr;
		__asm{
			mov eax, fs:[18h]
			mov eax, [eax+30h]
			movzx eax, byte ptr [eax+2h] 
			//call pFuncAddr
			//error?
			test eax,eax; 
			//error! 
			je rf_label; 
			//no error 
			pop eax; 
			test eax,eax 
			je rf_label; 
		} 
		//printf("eax:ture");
		return true;//is debugging
	rf_label: 
		return false; 
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

bool FD_NtQueryInfoProc_DbgPort() 
{ 
	PROCNTQSIP  pFuncAddr = GetNTQIPAddr();
	//printf("addr1:%x",pFuncAddr);
	if (NULL==pFuncAddr)
		return false;
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
		//printf("DbgPort:false");
		return false; 
	} 
}
bool FD_SeDebugPrivilege()
{
	char *pProcessName ="csrss.exe";
	DWORD dwCsrssPid = GetProcessIDByName(pProcessName);
	HANDLE hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS,false,dwCsrssPid);
	if(NULL!=hProcessHandle)
	{
		CloseHandle(hProcessHandle);
		//printf("FD_SeDebugPrivilege:true\n");
		return true;
	}
	//printf("FD_SeDebugPrivilege:false\n");
	return false;
}

bool FD_Parent_Process()
{
	//DWORD pFuncAddr = GetFuncAddr("kernel32","GetCurrentProcessID");
	DWORD dwMyProcessId = GetCurrentProcessId();
	//printf("dwMyProcessId:%x\n",dwMyProcessId);
	DWORD dwParentProcessId = GetParentProcessID(dwMyProcessId);
	//printf("dwParentProcessId:%x\n",dwParentProcessId);
	DWORD dwProcessId = GetProcessIDByName("explorer.exe");
	//printf("dwProcessId:%x\n",dwProcessId);

	if(dwProcessId == dwParentProcessId)
	{
		//printf("FD_Parent_Process:false\n");
		return false;
	}
	//printf("FD_Parent_Process:true\n");
	return true;
}
bool FD_NtQueryInfoProc_DbgFlags()
{
	PROCNTQSIP  pFuncAddr = GetNTQIPAddr();
	//printf("addr2:%x",pFuncAddr);
	if (NULL==pFuncAddr)
		return false;
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



int _tmain(int argc, _TCHAR* argv[])
{
	
	//if(FD_SeDebugPrivilege())
		//return 0;
	printf("[*] Zery has a ReMe for you , enjoy it !\n");
	char *flag1 = "6L+Z5Liq5LiN5pivZmxhZ+WTpg==";
	char inputstr[100];
    char inputstrfub[100];
	int yi = 0;
	int k = 0;
	char yistr[8];
	int p = 0;
	HANDLE hFile;
	__try
	{	
		__asm{
			xor eax,eax
			mov eax,[eax]
		}
		printf("[*] Plz input the flag:\n");
		scanf("%s",inputstr);
		if(strcmp(flag1,inputstr))
		{
			printf("[+]Congratulation!");
		}
		else
		{
			printf("[+]Wrong!");
		}
		Sleep(999999);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		__asm{
			sub esp ,4
				mov eax,SKIPBOARD1
				mov [esp],eax
				ret
		}
FUNC:
		if(FD_NtQueryInfoProc_DbgPort())
			return 0;
		hFile = CreateFile(LPCSTR("d:\\nottheflag.encrypt"),GENERIC_READ,          
							FILE_SHARE_READ,
							NULL,               
							OPEN_EXISTING,        
							FILE_ATTRIBUTE_NORMAL, 
							NULL);

		int fileret = (int)hFile;
		__asm{
			mov eax,fileret
			cmp eax,0
			jne SKIPBOARD2
			__emit 0xFF
		}
SKIPBOARD2:
		//35 6f 47 74 35 5a 61 63
		for (int i=0;i!=0x34;i++)
		{
			//yi += 1;
            inputstr[0] -= 1;
		}
		//yi = yi + 1;
		//yistr[0] = (char)yi;//35h
		DWORD dwtime = GetTickCount();
		if(FD_PEB_BeingDebuggedFlag())
			return 0;
		if (FD_Parent_Process())
			return 0;
        if(inputstr[0]==0x01)
        {
            //yi = p;
            for (int i=0;i!=0x37;i++)
            {
                //yi += 2;
                inputstr[1] -= 2;
            }
            //yi = yi + 1;
            //yistr[1] = (char)yi;//6fh
            if(inputstr[1]==0x01)
            {
                //yi = p;
                for (int i=0;i!=0x47;i++)
                {
                    //yi += 1;
                    inputstr[2] -= 1;
                }
               // yi = yi - 1;
                inputstr[2] += 1;
                //yistr[2] = (char)yi;//47h

				__asm{
					mov eax,dwtime
					cmp eax,0x11
					jge Next1
					__emit 0xEB
					__emit 0x00
					__emit 0x01
					__emit 0x5E
					__emit 0x14
					__emit 0xFF
				}
Next1:
				if(FD_NtQueryInfoProc_DbgFlags())
					return 0;
                if(inputstr[2]==0x01)
                {
                    //yi = p;
                    for (int i=0;i!=0x3A;i++)
                    {
                        //yi += 2;
                        inputstr[3] -= 2;
                    }
                   // yi = yi - 1;
                    inputstr[3] += 1;
                    //yistr[3] = (char)yi;//74h

                    if(inputstr[3]==0x01)
                    {
                       // yi = p;
                        for (int i=0;i!=0x35;i++)
                        {
                           // yi += 1;
                            inputstr[4] -= 1;
                        }
                        //yi = yi - 1;
                        inputstr[4] += 1;
                        //yistr[4] = (char)yi;//35h

                        if(inputstr[4]==0x01)
                        {
                            //yi = p;
                            for (int i=0;i!=0x2d;i++)
                            {
                                //yi += 2;
                                inputstr[5] -= 2;
                            }
                            //yi = yi - 1;
                            inputstr[5] += 1;
                            //yistr[5] = (char)yi;//5ah

                            if(inputstr[5]==0x01)
                            {
                                //yi = p;
                                for (int i=0;i!=0x30;i++)
                                {
                                    //yi += 2;
                                    inputstr[6] -= 2;
                                }
                                //yi = yi + 1;
                                //yistr[6] = (char)yi;//61h

                                if(inputstr[6]==0x01)
                                {
                                    //yi = p;
                                    for (int i=0;i!=0x31;i++)
                                    {
                                        //yi += 2;
                                        inputstr[7] -= 2;
                                    }
                                    //yi = yi + 1;
                                    //yistr[7] = (char)yi;//63h

                                    if(inputstr[7]==0x01)
                                    {
                                        if(!inputstr[8])
                                        {
											//printf("[+]Congratulation!");
                                            __asm{
                                                xor eax,eax
													 push eax
                                                cmp eax,0x08
                                                jne SKIPBOARD3
                                                __emit 0x8B
                                            }
                                        }
                                    }
                                    
                                }
                            }
                        }
                    }
                }
            }
        }
		printf("[+]Wrong!");
		__asm{
				mov ax,0x08EB
				push eax
				xor eax,eax
				jz END
				__emit 0xE8
		}
	
SKIPBOARD1:
		if(FD_IsDebuggerPresent())
			return 0;
		printf("[*] Plz input the flag:\n");
		scanf("%s",inputstr);
		p = (int)strcmp(flag1,inputstr);
        strcpy(inputstrfub,inputstr);
		k = p>>7;
		yi = p;
		__asm{jmp FUNC}
SKIPBOARD3:
			printf("[+]Congratulation!");
		__asm{jmp END}
END:
		__asm
        {
		    add esp ,4
	    }

		Sleep(999999);
	}
	return 0;
}

