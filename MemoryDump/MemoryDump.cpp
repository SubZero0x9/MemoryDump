 //Author: subzero0x9
 //Mail: subzero0x9@protonmail.com
 //Twitter: @subzero0x9

#include <iostream>
#include <Windows.h>
#include <DbgHelp.h>
#include <tchar.h>
#include <Psapi.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "Dbghelp.lib")

VOID WriteFullMemoryDump(HANDLE hprocess,WCHAR *filename);
VOID WriteMiniMemoryDump(HANDLE hprocess,WCHAR *filename);
BOOL EnableTokenPrivilege(LPTSTR LPrivilege);

int wmain(int argc, WCHAR *argv[])
{
	

	if (argc < 2)
	{
		printf("Usage: %s [options] [PID]\n", argv[0]);
		printf("options:- -fulldump : Create a full memory dump of the specified PID\n");
		printf("-fulldump : Create a full memory dump of the specified PID\n");
		printf("-minidump: Create a mini memory dump of the specified PID\n");
		return TRUE;
	}
	
	HANDLE hprocess;
	wchar_t ProcessName[MAX_PATH];
	int hproc = _wtoi(argv[2]);
	SYSTEMTIME logSystemUTC, logLocalUTC;
	wchar_t MiniDumpFileName[60];
	wchar_t FullDumpFileName[60];
	wchar_t HostName[MAX_PATH];
	DWORD HostNameSize = _countof(HostName);


	LPTSTR SeDebugPrivilege = (wchar_t*)SE_DEBUG_NAME;
	
	_tprintf(L"Enabling Required Privileges\n");
	if ((EnableTokenPrivilege(SeDebugPrivilege)) == TRUE)
	{
		_tprintf(L"Successfully Enabled SeDebugPrivilege\n");
	}
	
	
	hprocess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, hproc);
	if (!hprocess)
	{
		_tprintf(L"Cannot Open the specified Process. Failed with error code: %d\n", GetLastError());
	}
	else
	{

		if (!(GetModuleBaseName(hprocess, NULL, ProcessName, sizeof(ProcessName) / sizeof(TCHAR))))
		{
			_tprintf(L"Cannot Get Process Name. Failed with Error Code: %d\n", GetLastError());
		}
		else
		{
			_tprintf(L"Process Name :%s \n", ProcessName);
		}
	}

	if (!GetComputerNameW(HostName, &HostNameSize))
	{
		_tprintf(L"Cannot Get Host Name. Failed with Error Code: %d", GetLastError());
	}

	GetSystemTime(&logSystemUTC);
	SystemTimeToTzSpecificLocalTime(NULL, &logSystemUTC, &logLocalUTC);

	swprintf_s(MiniDumpFileName,_countof(MiniDumpFileName),L"C:\\%s_%d%d%d_MD_%s_%d.dmp", HostName, logLocalUTC.wYear, logLocalUTC.wMonth, logLocalUTC.wDay, ProcessName, hproc);
	swprintf_s(FullDumpFileName,_countof(FullDumpFileName),L"C:\\%s_%d%d%d_FD_%s_%d.dmp", HostName, logLocalUTC.wYear, logLocalUTC.wMonth, logLocalUTC.wDay, ProcessName, hproc);

		if (lstrcmpi(argv[1], TEXT("-fulldump")) == 0)
		{

			WriteFullMemoryDump(hprocess, FullDumpFileName);

		}
		else if (lstrcmpi(argv[1], TEXT("-minidump")) == 0)
		{
			WriteMiniMemoryDump(hprocess, MiniDumpFileName);
		}
		else
		{
			_tprintf(L"Choose a Valid Option\n");
		}
	
	return 0;
}


VOID WriteFullMemoryDump(HANDLE hprocess, WCHAR *filename)
{
		
	HANDLE hfile;
	BOOL DumpResult = FALSE;
	DWORD DumpTypeFlags = MiniDumpNormal | MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithProcessThreadData | MiniDumpWithFullMemoryInfo;
	WCHAR ProcName[MAX_PATH];

	hfile = CreateFile(filename, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!GetProcessImageFileName(hprocess, ProcName, _countof(ProcName)))
	{
		_tprintf(L"Cannot get Process File Name: %d", GetLastError());
	}


	if (!hfile)
	{
		_tprintf(L"File Cannot be created. Failed with Error code: %d \n", GetLastError());
	}
	else
	{
		DumpResult = MiniDumpWriteDump(hprocess, GetProcessId(hprocess), hfile, MINIDUMP_TYPE(DumpTypeFlags), NULL, NULL,NULL);
	
	}
	

	if (DumpResult == FALSE)
	{
		HRESULT errorcode = GetLastError();
		_tprintf(L"Memory Dump Failed with Error Code :%d\n", errorcode);
		CloseHandle(hprocess);
	}
	else
	{
		
		printf("Created Full Memory Dump Successfully\n");
		CloseHandle(hprocess);
	}
	
}

VOID WriteMiniMemoryDump(HANDLE hprocess, WCHAR *filename)
{
	HANDLE hfile;
	BOOL DumpResult = FALSE;
	DWORD DumpTypeFlags = MiniDumpNormal | MiniDumpWithThreadInfo  | MiniDumpWithTokenInformation | MiniDumpScanMemory | MiniDumpWithUnloadedModules | MiniDumpWithProcessThreadData | MiniDumpWithCodeSegs;
	hfile = CreateFile(filename, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!hfile)
	{
		_tprintf(L"File Cannot be created. Failed with Error code: %d \n", GetLastError());
	}
	else
	{
		DumpResult = MiniDumpWriteDump(hprocess, GetProcessId(hprocess), hfile, MINIDUMP_TYPE(DumpTypeFlags), NULL, NULL, NULL);

	}

	if (DumpResult == FALSE)
	{
		HRESULT errorcode = GetLastError();
		_tprintf(L"Memory Dump Failed with Error Code :%u\n", errorcode);
		CloseHandle(hprocess);
	}
	else
	{
			printf("Created Mini Memory Dump Successfully\n");
		CloseHandle(hprocess);
	}

}

BOOL EnableTokenPrivilege(LPTSTR LPrivilege)
{
	TOKEN_PRIVILEGES tp;
	BOOL bResult = FALSE;
	HANDLE hToken = NULL;
	
	ZeroMemory(&tp, sizeof(tp));
	tp.PrivilegeCount = 1;
	
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken) &&
		LookupPrivilegeValue(NULL, LPrivilege, &tp.Privileges[0].Luid))
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
	}
	else
	{
		_tprintf(L"Open Process Token Failed with Error Code: %d\n", GetLastError());
	}

	_tprintf(L"[-]Adjusted Token Attribute State: %d\n", tp.Privileges[0].Attributes);
	CloseHandle(hToken);

	return bResult;

}

