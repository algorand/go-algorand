//
// Algod Win32 Service Wrapper
//
// (c) Randlabs 2021.
//
#define UNICODE
#include "algodsvc.h"
#include "dprintf.h"
#include <Windows.h>
#include <vector>

//
// Globals
//
const int DEFAULT_WAIT_HINT_MS = 5000;
WCHAR g_serviceName[] = L"AlgodSvc";
WCHAR g_serviceDesc[] = L"Algorand Node Windows Service";
int g_svcCheckpoint = 0;
SERVICE_STATUS_HANDLE g_hSvc = NULL;
HANDLE g_hWaitAlgod = NULL;
PROCESS_INFORMATION g_algodProcInfo;
bool g_stopAllowed = false;

//
// Forward declarations
//
void WINAPI ServiceMain (DWORD dwNumServicesArgs, LPWSTR *lpServiceArgVectors);
void StopService();
DWORD HandlerProc(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext);
BOOL ServiceUpdateStatus(DWORD currentState, DWORD win32ExitCode,
                         DWORD serviceSpecificExitCode, DWORD checkPoint, DWORD waitHint);
BOOL LoadConfiguration(WCHAR* szAlgodExeFileName, DWORD* pcbAlgodExeFileName, WCHAR* szNodeDataDir,
                       DWORD* pcbNodeDataDir);
VOID CALLBACK AlgodWaitOrTimerCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired);
void Log(DWORD id, std::vector<LPCWSTR> insertionStrings);

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
        dprintfW(L"algodsvc: StartServiceCtrlDispatcher failed with error %d", GetLastError());
    }

    return status;
}

//
// The main routine for this service
//
void WINAPI ServiceMain (DWORD dwNumServicesArgs, LPWSTR *lpServiceArgVectors)
{
    g_hSvc = RegisterServiceCtrlHandlerEx(g_serviceName, HandlerProc, NULL);
    if (!g_hSvc)
    {
        dprintfW(L"algodsvc: RegisterServiceCtrlHandlerEx failed with error %d", GetLastError());
        return;
    }

    if (ServiceUpdateStatus(SERVICE_START_PENDING, 0, 0, g_svcCheckpoint++, DEFAULT_WAIT_HINT_MS))
    {
        // Start the algod node executable.

        WCHAR szAlgodExeFileName[MAX_PATH]{'\0'};
        WCHAR szNodeDataDir[MAX_PATH]{'\0'};
        DWORD cbAlgodExeFileName = MAX_PATH * sizeof(WCHAR), cbNodeDataDir = MAX_PATH * sizeof(WCHAR);

        if (!LoadConfiguration(szAlgodExeFileName, &cbAlgodExeFileName, szNodeDataDir, &cbNodeDataDir))
        {
            Log(MSG_ALGODSVC_CONFIGERROR, {});
            ServiceUpdateStatus(SERVICE_STOPPED, ERROR_BAD_CONFIGURATION, 0, g_svcCheckpoint++, DEFAULT_WAIT_HINT_MS);
            return;
        }

        dprintfW(L"algodsvc: Configuration loaded. AlgodExeFilename=%s NodeDataDir=%s", szAlgodExeFileName, szNodeDataDir);

        WCHAR szCmdLine[1024]{'\0'};
        wcsncpy(szCmdLine, szAlgodExeFileName, wcslen(szAlgodExeFileName));
        wcsncat(szCmdLine, L" -d ", 4);
        wcsncat(szCmdLine, szNodeDataDir, wcslen(szNodeDataDir));

        STARTUPINFO si;
        ZeroMemory(&si, sizeof(STARTUPINFO));
        ZeroMemory(&g_algodProcInfo, sizeof(PROCESS_INFORMATION));

        dprintfW(L"algodsvc: invoking: %s %s", szAlgodExeFileName, szCmdLine);
        if (!CreateProcessW(NULL, szCmdLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &g_algodProcInfo))
        {
            dprintfW(L"algodsvc: CreateProcess failed. Win32 Err: %d", GetLastError());

            wchar_t lasterr[255];
            StringCchPrintfW(lasterr, 255, L"%d", GetLastError());
            Log(MSG_ALGODSVC_CREATEPROCESS, { lasterr });

            ServiceUpdateStatus(SERVICE_STOPPED, GetLastError(), 0, g_svcCheckpoint++, DEFAULT_WAIT_HINT_MS);
            return;
        }

        if (!RegisterWaitForSingleObject(&g_hWaitAlgod, g_algodProcInfo.hProcess, AlgodWaitOrTimerCallback, NULL, INFINITE, WT_EXECUTEONLYONCE))
        {
            dprintfW(L"algodsvc: RegisterWaitForSingleObject failed. Win32 Err: %d", GetLastError());
            ServiceUpdateStatus(SERVICE_STOPPED, GetLastError(), 0, g_svcCheckpoint++, DEFAULT_WAIT_HINT_MS);
            return;
        }

        // We are finally booted up.

        g_stopAllowed = true;
        ServiceUpdateStatus(SERVICE_RUNNING, NO_ERROR, 0, g_svcCheckpoint++, DEFAULT_WAIT_HINT_MS);
        Log(MSG_ALGODSVC_STARTED, { szAlgodExeFileName, szNodeDataDir });
    }
}

//
// Handles the algod process termination and stop the service.
//
VOID CALLBACK AlgodWaitOrTimerCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
{
    DWORD dwExit;
    GetExitCodeProcess(g_algodProcInfo.hProcess, &dwExit);
    dprintfW(L"algodsvc: Process terminated. Exit Code = %d", dwExit);

    ServiceUpdateStatus(SERVICE_STOP_PENDING, dwExit == 0 ? NO_ERROR : ERROR_PROCESS_ABORTED, 0, 1, DEFAULT_WAIT_HINT_MS);
    if (dwExit == 0)
    {
        Log(MSG_ALGODSVC_EXIT, {});
    }
    else
    {
        wchar_t exit[255];
        StringCchPrintfW(exit, 255, L"%d", dwExit);
        Log(MSG_ALGODSVC_TERMINATED, {exit});
    }

    BOOL ret = UnregisterWait(g_hWaitAlgod);
    if (!ret && GetLastError() != ERROR_IO_PENDING)
    {
        dprintfW(L"algodsvc: UnregisterWait returned error %d", GetLastError());
        return;
    }

    CloseHandle(g_algodProcInfo.hProcess);
    CloseHandle(g_algodProcInfo.hThread);

    ServiceUpdateStatus(SERVICE_STOPPED, dwExit == 0 ? NO_ERROR : ERROR_PROCESS_ABORTED, 0, 2, DEFAULT_WAIT_HINT_MS);
}

//
// Loads the configuration keys for this service from Windows registry.
//
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
        dprintfW(L"algodsvc: Configuration error, service algodsvc key not found.");
        return FALSE;
    }

    LRESULT l0 = RegQueryValueEx(hKey, L"AlgodExeFileName", 0, &dwType, (BYTE *)szAlgodExeFileName, pcbAlgodExeFileName);
    LRESULT l1 = RegQueryValueEx(hKey, L"NodeDataDirectory", 0, &dwType, (BYTE *)szNodeDataDir, pcbNodeDataDir);
    RegCloseKey(hKey);

    if (l0 != ERROR_SUCCESS || l1 != ERROR_SUCCESS || *pcbAlgodExeFileName <= 2 || *pcbNodeDataDir <= 2)
    {
        dprintfW(L"algodsvc:  Configuration error, check missing keys");
        return FALSE;
    }

    return TRUE;
}

//
// SCM Service status callback handling routine.
//
DWORD HandlerProc(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
    DWORD status = NO_ERROR;
    switch(dwControl)
    {
        case SERVICE_CONTROL_SHUTDOWN:
        case SERVICE_CONTROL_STOP:
            StopService();
            break;
        break;
        case SERVICE_CONTROL_INTERROGATE:
            break;
        default:
            status = ERROR_CALL_NOT_IMPLEMENTED;
    }
    return status;
}

//
// Do the chores to stop the service, which involves requesting
// our algod child process to exit accordingly.
//
void StopService()
{
    g_svcCheckpoint = 0;
    if(ServiceUpdateStatus(SERVICE_STOP_PENDING, NO_ERROR, 0, g_svcCheckpoint++, DEFAULT_WAIT_HINT_MS))
    {
        // This hack attaches temporarily our process to the algod.exe spawned console,
        // so we are in a console process group, and send a Ctrl+C signal to trigger a proper exit.
        // Just to be safe, we disable ctrl-c events for our own service.

        // Keep in mind that we dont stop the service here but wait for the process
        // termination callback AlgodWaitOrTimerCallback to do it when algod exits.
        // If for any reason that does not get called, the service will terminate after timeout.

        dprintfW(L"Algodsvc: SERVICE_STOP_PENDING set. Sending CTRL_C_EVENT to algod PID %d", g_algodProcInfo.dwProcessId);

        FreeConsole();
        if (AttachConsole(g_algodProcInfo.dwProcessId))
        {
            SetConsoleCtrlHandler(NULL, true);
            if (!GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0))
            {
                dprintfW(L"Algodsvc: GenerateConsoleCtrlEvent failed with err: %d", GetLastError());
            }
            FreeConsole();
        }
        else
        {
            dprintfW(L"Algodsvc: AttachConsole failed with err: %d", GetLastError());
        }
    }
}

//
// Report the SCM a status change.
//
BOOL ServiceUpdateStatus(DWORD currentState, DWORD win32ExitCode,
                         DWORD serviceSpecificExitCode, DWORD checkPoint, DWORD waitHint)
{
    SERVICE_STATUS ss;
    ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ss.dwCurrentState = currentState;
    ss.dwServiceSpecificExitCode = serviceSpecificExitCode;
    ss.dwCheckPoint = checkPoint;
    ss.dwWaitHint = waitHint;
    ss.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN | (g_stopAllowed ? SERVICE_ACCEPT_STOP : 0);
    ss.dwWin32ExitCode =
        serviceSpecificExitCode == 0
            ? win32ExitCode
            : ERROR_SERVICE_SPECIFIC_ERROR;

    if (currentState == SERVICE_STOPPED)
    {
        Log(MSG_ALGODSVC_STOPPED,{});
    }

    BOOL ret =  SetServiceStatus(g_hSvc, &ss);
    if(!ret)
        dprintfW(L"algodsvc: SetServiceStatus to 0x%08x returned error %d", currentState, GetLastError() );

    return ret;
}

//
// Converts message-file severity codes to Eventlog Entry types.
//
WORD SeverityToEventType(DWORD id)
{
    return ((id >> 30) == STATUS_SEVERITY_ERROR) ? EVENTLOG_ERROR_TYPE :
        (((id >> 30) == STATUS_SEVERITY_INFORMATIONAL) ? EVENTLOG_INFORMATION_TYPE :
        EVENTLOG_WARNING_TYPE);
}

//
// Write an entry to the Windows Log.
//
void Log(DWORD id, std::vector<LPCWSTR> insertionStrings)
{
    HANDLE hEventSrc = RegisterEventSource(NULL, L"Algorand Node Service");
    if (!hEventSrc)
    {
        dprintfW(L"algodsvc: Cannot register event source. Error is %d", GetLastError());
        return;
    }

    dprintfW(L"id=0x%08x ev= %d", id, SeverityToEventType(id));

    //  NOTE: &rgMsg[0] is possible due to C++ spec where std::vector is contiguous in memory.

    ReportEventW(hEventSrc, SeverityToEventType(id), 0, id, NULL, insertionStrings.size(), 0, &insertionStrings[0], NULL);
    DeregisterEventSource(hEventSrc);
}