//
// Algod Win32 Service Wrapper
//
// (c) Randlabs 2021.
//
#define UNICODE

#include "dprintf.h"
#include <Windows.h>

//
// Globals
//
const int DEFAULT_WAIT_HINT_MS = 1000;
WCHAR g_serviceName[] = L"AlgodSvc";
WCHAR g_serviceDesc[] = L"Algorand Node Windows Service";
int g_svcCheckpoint = 0;
SERVICE_STATUS_HANDLE g_hSvc = NULL;
HANDLE g_hWaitAlgod = NULL;

//
// Forward declarations
//
void WINAPI ServiceMain (DWORD dwNumServicesArgs, LPWSTR *lpServiceArgVectors);
DWORD InstallService();
DWORD HandlerProc(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext);
BOOL ServiceUpdateStatus(DWORD currentState, DWORD win32ExitCode, 
                         DWORD serviceSpecificExitCode, DWORD checkPoint, DWORD waitHint);
BOOL LoadConfiguration(WCHAR* szAlgodExeFileName, DWORD* pcbAlgodExeFileName, WCHAR* szNodeDataDir, 
                       DWORD* pcbNodeDataDir);
VOID CALLBACK AlgodWaitOrTimerCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired);

// --------------------------------------------------------------------------------------------------
//
// Program Entry point.
//
// --------------------------------------------------------------------------------------------------
int main(int argc, char** argv)
{
    int status = 0;

    SERVICE_TABLE_ENTRY serviceTable[] =
    {
        {g_serviceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    if (!StartServiceCtrlDispatcher(serviceTable))
    {
        status = static_cast<int>(GetLastError());
        //     SvcReportEvent(TEXT("StartServiceCtrlDispatcher"));
    }

    return status;
}

void WINAPI ServiceMain (DWORD dwNumServicesArgs, LPWSTR *lpServiceArgVectors)
{
    g_hSvc = RegisterServiceCtrlHandlerEx(g_serviceName, HandlerProc, NULL);
    if (!g_hSvc)
    {
        OutputDebugString(L"RegisterServiceCtrlHandlerEx failed");
        return;
    }

    if (!ServiceUpdateStatus(SERVICE_START_PENDING, 0, 0, g_svcCheckpoint++, DEFAULT_WAIT_HINT_MS))
    {
        OutputDebugString(L"ServiceUpdateStatus failed");
        return;
    }

    // Start the algod node executable.

    WCHAR szAlgodExeFileName[MAX_PATH]{'\0'};
    WCHAR szNodeDataDir[MAX_PATH]{'\0'};
    DWORD cbAlgodExeFileName = MAX_PATH * sizeof(WCHAR), cbNodeDataDir = MAX_PATH * sizeof(WCHAR);

    if (!LoadConfiguration(szAlgodExeFileName, &cbAlgodExeFileName, szNodeDataDir, &cbNodeDataDir))
    {
        ServiceUpdateStatus(SERVICE_STOPPED, ERROR_BAD_CONFIGURATION, 0, g_svcCheckpoint++, DEFAULT_WAIT_HINT_MS);
        return;
    }

    dprintfW(L"Configuration loaded. AlgodExeFilename=%s NodeDataDir=%s", szAlgodExeFileName, szNodeDataDir);

    WCHAR szCmdLine[1024] {'\0'};
    wcsncpy(szCmdLine, szAlgodExeFileName, wcslen(szAlgodExeFileName));
    wcsncat(szCmdLine, L" -d ", 4);
    wcsncat(szCmdLine, szNodeDataDir, wcslen(szNodeDataDir));

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(STARTUPINFO));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    dprintfW(L"invoking: %s %s", szAlgodExeFileName, szCmdLine);
    if (!CreateProcessW(NULL, szCmdLine, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi))
    {
        dprintfW(L"CreateProcess failed. Win32 Err: %d", GetLastError());
        ServiceUpdateStatus(SERVICE_STOPPED, GetLastError(), 0, g_svcCheckpoint++, DEFAULT_WAIT_HINT_MS);
        return;
    }
    
    if (!RegisterWaitForSingleObject(&g_hWaitAlgod, pi.hProcess, AlgodWaitOrTimerCallback, pi.hProcess, INFINITE, WT_EXECUTEONLYONCE))
    {
        dprintfW(L"RegisterWaitForSingleObject failed. Win32 Err: %d", GetLastError());
        ServiceUpdateStatus(SERVICE_STOPPED, GetLastError(), 0, g_svcCheckpoint++, DEFAULT_WAIT_HINT_MS);
        return;
    }
    
    // We are finally booted up.
    if (!ServiceUpdateStatus(SERVICE_RUNNING, NO_ERROR, 0, g_svcCheckpoint++, DEFAULT_WAIT_HINT_MS))
        dprintfW(L"ServiceUpdateStatus returned error %d", GetLastError() );
}

VOID CALLBACK AlgodWaitOrTimerCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
{
    DWORD dwExit;
    GetExitCodeProcess((HANDLE) lpParameter, &dwExit);
    dprintfW(L"Process terminated. Exit Code = %d", dwExit);

    if (!ServiceUpdateStatus(SERVICE_STOPPED, dwExit == 0 ? NO_ERROR : ERROR_PROCESS_ABORTED, 0, 1, DEFAULT_WAIT_HINT_MS))
    {
        dprintfW(L"ServiceUpdateStatus returned error %d", GetLastError() );
        return;
    }
    
    BOOL ret = UnregisterWait(g_hWaitAlgod);
    if (!ret && GetLastError() != ERROR_IO_PENDING)
    {
        dprintfW(L"UnregisterWait returned error %d", GetLastError());
        return;
    }

    CloseHandle((HANDLE)lpParameter);
}

BOOL LoadConfiguration(WCHAR* szAlgodExeFileName, DWORD* pcbAlgodExeFileName, 
                       WCHAR* szNodeDataDir, DWORD* pcbNodeDataDir) 
{
    WCHAR szSubkey[255]; 
    wcsncpy(szSubkey, L"SYSTEM\\CurrentControlSet\\Services\\", 34);
    wcsncat(szSubkey, g_serviceName, wcslen(g_serviceName));
    wcsncat(szSubkey, L"\\Parameters", 11);

    HKEY hKey;
    DWORD dwType = REG_SZ;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szSubkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        OutputDebugString(L"Configuration error, service algodsvc key not found.");
        return FALSE;
    }

    LRESULT l0 = RegQueryValueEx(hKey, L"AlgodExeFileName", 0, &dwType, (BYTE *)szAlgodExeFileName, pcbAlgodExeFileName);
    LRESULT l1 = RegQueryValueEx(hKey, L"NodeDataDirectory", 0, &dwType, (BYTE *)szNodeDataDir, pcbNodeDataDir);
    RegCloseKey(hKey);
 
    if (l0 != ERROR_SUCCESS || l1 != ERROR_SUCCESS || *pcbAlgodExeFileName <= 2 || *pcbNodeDataDir <= 2)
    {
        OutputDebugString(L"Configuration error, check missing keys");
        return FALSE;
    }

    return TRUE;
}

DWORD HandlerProc(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
    DWORD status = NO_ERROR;
    switch(dwControl)
    {
        case SERVICE_CONTROL_SHUTDOWN:
	    case SERVICE_CONTROL_STOP:
		    ServiceUpdateStatus(SERVICE_STOPPED, NO_ERROR, 0, 0, DEFAULT_WAIT_HINT_MS);
        break;
        case SERVICE_CONTROL_INTERROGATE:
            break;
        default:
            status = ERROR_CALL_NOT_IMPLEMENTED;
    }
    return status;
}

BOOL ServiceUpdateStatus(DWORD currentState, DWORD win32ExitCode, 
                         DWORD serviceSpecificExitCode, DWORD checkPoint, DWORD waitHint)
{
	SERVICE_STATUS ss;
	ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ss.dwCurrentState = currentState;
	ss.dwServiceSpecificExitCode = serviceSpecificExitCode;
	ss.dwCheckPoint = checkPoint;
	ss.dwWaitHint = waitHint;
	ss.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ss.dwWin32ExitCode = 
		serviceSpecificExitCode == 0
			? win32ExitCode
			: ERROR_SERVICE_SPECIFIC_ERROR;

	return SetServiceStatus(g_hSvc, &ss);
}

//
// Write an entry to the Windows Log. 
// 
//void Log(int severity,  )