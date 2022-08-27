// windows-event-viewer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// help: [ https://docs.microsoft.com/en-us/windows/win32/wes/querying-for-events ]
// help: [ https://docs.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtquery ]
// help: [ https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_query_flags ]
// help: [ https://gist.github.com/Mandar-Shinde/6468275f9cbaecf61807a8ca3ad78c10 ] - contains some different channel and filter, hence it works, but values from EventViewer do not work
// help: [ https://docs.microsoft.com/en-us/windows/win32/wes/rendering-events ]
// help: [ https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events?source=recommendations ]
// help: [ https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-account-logon-events ]
// help: [ https://www.manageengine.com/products/active-directory-audit/kb/windows-security-log-event-id-4624.html ] - EventID=4624 for successful login, EventID=4625 for failed login
// help: [ https://www.w3schools.com/xml/xpath_syntax.asp ] - how to formulate XPath 1.0 query instead of sending the XML query string

// help: [ https://www.manageengine.com/network-monitoring/Eventlog_Tutorial_Part_I.html ] - lists how events are structured in windows
// help: [ https://www.manageengine.com/network-monitoring/Eventlog_Tutorial_Part_II.html ] - lists some of the EventIDs that are of interest
// help: [ https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ ] - more EventIDs

// help: [ https://docs.microsoft.com/en-us/cpp/cpp/main-function-command-line-args?view=msvc-170#customize ] - adding command line arguments and processing the list of arguments
// help: [ https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499- ] - maintain consistency with windows error codes meaning

#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <winevt.h>
#include <strsafe.h>

#pragma comment(lib, "wevtapi.lib")

#define ARRAY_SIZE 10
#define TIMEOUT 1000  // 1 second; Set and use in place of INFINITE in EvtNext call

#define MAX_PATH_LONG 32767 + 1 // need to alocate max buffer for paths, then interpolate and use smaller buffer, supposedly can support even longer paths, help: [ https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=registry ]



// ************************************ EVENTS ************************************
void DisplayError(LPCWSTR lpszFunction)
// Routine Description:
// Retrieve and output the system error message for the last-error code
{
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0,
        NULL);

    lpDisplayBuf =
        (LPVOID)LocalAlloc(LMEM_ZEROINIT,
            (lstrlen((LPCTSTR)lpMsgBuf)
                + lstrlen((LPCTSTR)lpszFunction)
                + 40) // account for format string
            * sizeof(TCHAR));

    if (FAILED(StringCchPrintf((LPTSTR)lpDisplayBuf,
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error code %d as follows:\n%s"),
        lpszFunction,
        dw,
        lpMsgBuf)))
    {
        printf("FATAL ERROR: Unable to output error code.\n");
    }

    wprintf(TEXT("ERROR: %s\n"), (LPCTSTR)lpDisplayBuf);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}

//void WriteFile(LPCWSTR pwsDump)
//{
//    // help: [ https://docs.microsoft.com/en-us/windows/win32/fileio/opening-a-file-for-reading-or-writing ]
//    // todo: need to open file handle, then dump items one by one, and finally close the file and ensure its written, 
//    // todo: to be on the safe side, every couple of items need to close the file to have the files available
//    HANDLE hFile;
//    char DataBuffer[] = "This is some test data to write to the file.";
//    DWORD dwBytesToWrite = (DWORD)strlen(DataBuffer);
//    DWORD dwBytesWritten = 0;
//    BOOL bErrorFlag = FALSE;
//
//    hFile = CreateFile(pwsDump,                // name of the write
//                       GENERIC_WRITE,          // open for writing
//                       0,                      // do not share
//                       NULL,                   // default security
//                       CREATE_NEW,             // create new file only
//                       FILE_ATTRIBUTE_NORMAL,  // normal file
//                       NULL);                  // no attr. template
//
//    if (hFile == INVALID_HANDLE_VALUE)
//    {
//        DisplayError(L"CreateFile");
//        wprintf(L"Terminal failure: Unable to open file \"%s\" for write.\n", pwsDump);
//        return;
//    }
//
//    wprintf(TEXT("Writing %d bytes to %s.\n"), dwBytesToWrite, pwsDump);
//
//    bErrorFlag = WriteFile(
//        hFile,           // open file handle
//        DataBuffer,      // start of data to write
//        dwBytesToWrite,  // number of bytes to write
//        &dwBytesWritten, // number of bytes that were written
//        NULL);            // no overlapped structure
//
//    if (FALSE == bErrorFlag)
//    {
//        DisplayError(L"WriteFile");
//        wprintf(L"Terminal failure: Unable to write to file.\n");
//    }
//    else
//    {
//        if (dwBytesWritten != dwBytesToWrite)
//        {
//            // This is an error because a synchronous write that results in
//            // success (WriteFile returns TRUE) should write all data as
//            // requested. This would not necessarily be the case for
//            // asynchronous writes.
//            wprintf(L"Error: dwBytesWritten != dwBytesToWrite\n");
//        }
//        else
//        {
//            wprintf(L"Wrote %d bytes to %s successfully.\n", dwBytesWritten, pwsDump);
//        }
//    }
//
//    CloseHandle(hFile);
//}

DWORD PrintEvent(EVT_HANDLE hEvent, HANDLE hFile)
{
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    LPWSTR pRenderedContent = NULL;

    DWORD dwBytesToWrite = 0;
    DWORD dwBytesWritten = 0;
    BOOL bErrorFlag = FALSE;

    // The EvtRenderEventXml flag tells EvtRender to render the event as an XML string.
    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
    {
        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedContent = (LPWSTR)malloc(dwBufferSize);
            if (pRenderedContent)
            {
                EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
                wprintf(L"malloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != (status = GetLastError()))
        {
            wprintf(L"EvtRender failed with %d\n", GetLastError());
            goto cleanup;
        }
    }

    wprintf(L"\n\n%s", pRenderedContent);

    if (INVALID_HANDLE_VALUE != hFile) 
    {
        dwBytesToWrite = (wcslen(pRenderedContent) + 1) * sizeof(WCHAR);
        bErrorFlag = WriteFile(hFile,               // open file handle
                               pRenderedContent,    // start of data to write
                               dwBytesToWrite,      // number of bytes to write
                               &dwBytesWritten,     // number of bytes that were written
                               NULL);               // no overlapped structure

        if (FALSE == bErrorFlag)
        {
            DisplayError(L"WriteFile");
            wprintf(L"Terminal failure: Unable to write to file.\n");
        }
        else
        {
            if (dwBytesWritten != dwBytesToWrite)
            {
                // This is an error because a synchronous write that results in
                // success (WriteFile returns TRUE) should write all data as
                // requested. This would not necessarily be the case for
                // asynchronous writes.
                wprintf(L"Error: dwBytesWritten != dwBytesToWrite\n");
            }
            else
            {
                //wprintf(L"Wrote [%d] bytes to [%s] successfully.\n", dwBytesWritten, pwsDumpFolder);
            }
        }
    }

cleanup:

    if (pRenderedContent)
        free(pRenderedContent);

    return status;
}

// Enumerate all the events in the result set. 
DWORD PrintResults(EVT_HANDLE hResults, LPCWSTR pwsDumpFile)
{
    // help: [ https://docs.microsoft.com/en-us/windows/win32/fileio/opening-a-file-for-reading-or-writing ]
    // todo: need to open file handle, then dump items one by one, and finally close the file and ensure its written, 
    // todo: to be on the safe side, every couple of items need to close the file to have the files available
    HANDLE hFile = INVALID_HANDLE_VALUE;
    //char DataBuffer[] = "This is some test data to write to the file.";
    //DWORD dwBytesToWrite = (DWORD)strlen(DataBuffer);
    //DWORD dwBytesWritten = 0;
    BOOL bErrorFlag = FALSE;

    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hEvents[ARRAY_SIZE];
    DWORD dwReturned = 0;

    // open file for writing - generate file only - will fail if file already exists
    hFile = CreateFile(pwsDumpFile, // name of the write
        GENERIC_WRITE,              // open for writing
        0,                          // do not share
        NULL,                       // default security
        CREATE_NEW,                 // create new file only
        FILE_ATTRIBUTE_NORMAL,      // normal file
        NULL);                      // no attr. template

    if (hFile == INVALID_HANDLE_VALUE)
    {
        DisplayError(L"CreateFile");
        wprintf(L"Terminal failure: Unable to open file \"%s\" for write.\n", pwsDumpFile);
        return ERROR_INVALID_HANDLE;
    }

    while (true)
    {
        // Get a block of events from the result set.
        if (!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned))
        {
            if (ERROR_NO_MORE_ITEMS != (status = GetLastError()))
            {
                wprintf(L"EvtNext failed with %lu\n", status);
            }

            goto cleanup;
        }

        // For each event, call the PrintEvent function which renders the
        // event for display. PrintEvent is shown in RenderingEvents.
        for (DWORD i = 0; i < dwReturned; i++)
        {
            if (ERROR_SUCCESS == (status = PrintEvent(hEvents[i], hFile)))
            {
                EvtClose(hEvents[i]);
                hEvents[i] = NULL;
            }
            else
            {
                goto cleanup;
            }
        }
    }

cleanup:
    // close the file - without this the file is not finalized, and it can get corrupted
    CloseHandle(hFile);

    for (DWORD i = 0; i < dwReturned; i++)
    {
        if (NULL != hEvents[i])
            EvtClose(hEvents[i]);
    }

    return status;
}

DWORD QueryEvents(LPCWSTR pwsPath, LPCWSTR pwsQuery, LPCWSTR pwsDumpFile)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL;

    hResults = EvtQuery(NULL, pwsPath, pwsQuery, EvtQueryFilePath | EvtQueryReverseDirection);
    // hResults = EvtQuery(NULL, pwsPath, pwsQuery, EvtQueryChannelPath | EvtQueryReverseDirection); // why cant use [ Microsoft-Windows-Security-Auditing ] // %SystemRoot%\System32\Winevt\Logs\Security.evtx
    if (NULL == hResults)
    {
        status = GetLastError();

        if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
            wprintf(L"The channel was not found.\n");
        else if (ERROR_EVT_INVALID_QUERY == status)
            // You can call the EvtGetExtendedStatus function to try to get 
            // additional information as to what is wrong with the query.
            wprintf(L"The query is not valid.\n");
        else if (ERROR_ACCESS_DENIED == status)
            wprintf(L"Access denied to run query. Try running as Admin.\n");
        else
            wprintf(L"EvtQuery failed with %lu.\n", status);

        goto cleanup;
    }

    PrintResults(hResults, pwsDumpFile);

cleanup:

    if (hResults)
        EvtClose(hResults);

    return status;

}
// **************************************** ****************************************



// *********************************** TIMESTAMPS **********************************
// help: [ https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtime?redirectedfrom=MSDN ]
// help: [ https://docs.microsoft.com/en-us/cpp/mfc/memory-management-examples?view=msvc-170 ]
// help: [ https://docs.microsoft.com/en-us/cpp/c-runtime-library/string-manipulation-crt?source=recommendations&view=msvc-170 ]

const LPCWSTR TIMESTAMP_FORMAT = L"%04d-%02d-%02d_%02d-%02d-%02d.%03d";
const int TIMESTAMP_SIZE = 24; // 4-2-2_2-2-2.3 = 17 + separators = 17 + 6 = 23 + end

LPWSTR GetSystemTimestamp()
{
    SYSTEMTIME st;

    // Allocate on the heap
    LPWSTR timestamp = new WCHAR[TIMESTAMP_SIZE];

    GetSystemTime(&st);
    swprintf(timestamp, TIMESTAMP_SIZE, TIMESTAMP_FORMAT, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    // wprintf(L"The system time is: %04d-%02d-%02d_%02d-%02d-%02d.%03d\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    return timestamp;
}

LPWSTR GetLocalTimestamp()
{
    SYSTEMTIME lt;

    // Allocate on the heap
    LPWSTR timestamp = new WCHAR[TIMESTAMP_SIZE];

    GetLocalTime(&lt);
    swprintf(timestamp, TIMESTAMP_SIZE, TIMESTAMP_FORMAT, lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);
    // wprintf(L" The local time is: %04d-%02d-%02d_%02d-%02d-%02d.%03d\n", lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);

    return timestamp;
}
// **************************************** ****************************************



// *********************************INTERPOLATIONS *********************************
LPWSTR InterpolateString(LPCWSTR string)
{
    // help: [ https://docs.microsoft.com/en-us/windows/win32/procthread/changing-environment-variables ]
    // help: [ https://docs.microsoft.com/en-us/windows/win32/api/strsafe/nf-strsafe-stringcchcopyexw ] - overly engineered string functions that consume a lot of time to write with and do not actually bring the NEEDED functionality to strings

    LPWSTR buffer = new WCHAR[MAX_PATH_LONG];
    LPWSTR env_var_name = new WCHAR[MAX_PATH]; // note: environment variable names cannot go beyond 260
    LPWSTR env_var_value = new WCHAR[MAX_PATH_LONG]; // note: environment variable value can go all the way to 32767 

    LPWSTR result = NULL;
    DWORD status = ERROR_SUCCESS;
    DWORD lastError = ERROR_SUCCESS;

    ZeroMemory(buffer, MAX_PATH_LONG); // note: in order to be able to use string copy functions

    for (int i = 0, j = 0; i <= wcslen(string); i++)
    {
        if (L'%' == string[i]) // todo: need to validate that there are an even number of L'%' wchars, or the interpolation fails
        {
            // note: need to find the next % and get the value in between as [env_var_name]
            int k = 0;
            while (string[i + k + 1] != L'%')
            {
                env_var_name[k] = string[i + k + 1];
                k++;
            }
            env_var_name[k] = L'\0';

            if (ERROR_SUCCESS != (status = GetEnvironmentVariableW(env_var_name, env_var_value, MAX_PATH_LONG)))
            {
                lastError = GetLastError();
                if (ERROR_ENVVAR_NOT_FOUND == lastError)
                {
                    wprintf(L"Environment variable [%s] does not exist.\n", env_var_name);
                    swprintf(env_var_value, MAX_PATH_LONG, L"_%s_VAR_NOT_FOUND_", env_var_name); // note: [comment1] continue despite error, need to figure out what to replace invalid interpolation parameter, perhaps a hardcoded string value
                }
            }
            // else // note: related to [comment1], continue even if variable was not found
            //{
            // note: copy the interpolated value into the buffer containing raw path
            wcscat_s(buffer, MAX_PATH_LONG, env_var_value);
            j += wcslen(env_var_value);
            //}
            i = i + k + 1;
        }
        else
        {
            buffer[j] = string[i];
            j++;
        }
    }

    // note: before returning, use a smaller capped buffer, that is precisely the size of the string
    result = (LPWSTR)malloc((wcslen(buffer) + 1) * sizeof(WCHAR));
    wcscpy_s(result, wcslen(buffer) + 1, buffer);

cleanup:
    free(buffer);
    free(env_var_name);
    free(env_var_value);

    return result;
}

LPWSTR ConstructFilename(LPCWSTR pwsDumpFolder)
{
    LPWSTR buffer = new WCHAR[MAX_PATH_LONG];
    LPWSTR module = new WCHAR[MAX_PATH_LONG];

    LPWSTR result = NULL;
    DWORD status = ERROR_SUCCESS;
    DWORD lastError = ERROR_SUCCESS;

    ZeroMemory(buffer, MAX_PATH_LONG); // note: in order to be able to use string copy functions
    ZeroMemory(module, MAX_PATH_LONG); // note: in order to be able to use string copy functions

    LPWSTR interpolated = NULL;
    interpolated = InterpolateString(pwsDumpFolder);
    wcscpy_s(buffer, MAX_PATH_LONG, interpolated); // note: copy base path interpolated to the new constructed path
    //free(interpolated);

    if (L'\\' != buffer[wcslen(buffer)])
        wcscat_s(buffer, MAX_PATH_LONG, L"\\"); // note: add folder sepparator if not present

    LPWSTR timestamp = NULL;
    timestamp = GetLocalTimestamp();
    wcscat_s(buffer, MAX_PATH_LONG, timestamp); // note: copy base path interpolated to the new constructed path
    //free(timestamp);

    // note: suffix with filename of this executable

    // help: [ https://stackoverflow.com/questions/12254980/how-to-get-the-filename-of-the-currently-running-executable-in-c ] - the general idea
    // help: [ https://github.com/mirror/boost/blob/master/libs/log/src/process_name.cpp ] - interesting resizing mechanic for windows methods
    // help: can use windows kernel function, or pass in the argv[0] from main function which contains full path of current program
    GetModuleFileNameW(NULL, module, MAX_PATH_LONG);

    // iterate path to the last separator \\ 
    int i = wcslen(module);
    while (L'\\' != module[i]) i--;

    wcscat_s(buffer, MAX_PATH_LONG, L"_");
    wcscat_s(buffer, MAX_PATH_LONG, (LPWSTR) &module[i+1]); // note: string starting at position i should contain only the filename of executable
    //free(module);
    buffer[wcslen(buffer) - 4] = L'\0'; // note: strip [.exe] from filename 
    wcscat_s(buffer, MAX_PATH_LONG, L".xml"); // note: top up with xml extension

    // note: before returning, use a smaller capped buffer, that is precisely the size of the string
    result = (LPWSTR)malloc((wcslen(buffer) + 1) * sizeof(WCHAR));
    wcscpy_s(result, wcslen(buffer) + 1, buffer);

cleanup:
    free(interpolated);
    free(module);
    free(timestamp);
    free(buffer);

    return result;
}
// **************************************** ****************************************



// ************************************* TESTS *************************************
void RunTests()
{
    // Test 1 - GetSystemTimestamp
    LPWSTR timestamp = NULL;
    timestamp = GetSystemTimestamp();
    wprintf(L"System timestamp: %s\n", timestamp);
    free(timestamp);

    // Test 2 - GetLocalTimestamp
    timestamp = GetLocalTimestamp();
    wprintf(L"Local timestamp: %s\n", timestamp);
    free(timestamp);

    const LPCWSTR pwsDumpFolder = L"c:\\Users\\%username%\\Downloads"; // will have to interpolate value %username% before using the path

    // Test 3 - InterpolateString
    LPWSTR interpolated = NULL;
    interpolated = InterpolateString(pwsDumpFolder);
    wprintf(L"InterpolateString(%s)=%s\n", pwsDumpFolder, interpolated);
    free(interpolated);

    // Test 4 - ConstructFilename
    LPWSTR pwsDumpFile = NULL;
    pwsDumpFile = ConstructFilename(pwsDumpFolder);
    wprintf(L"ConstructFilename(%s)=%s\n", pwsDumpFolder, pwsDumpFile);
    free(pwsDumpFile);
}
// **************************************** ****************************************



// ************************************ CONSOLE ************************************
void PrintHelp(wchar_t* argv[])
{
    wprintf(L"\nPrintHelp:\n");
    wprintf(L"\"%s\" [PathToEventFile] [XPathFormattedQuery] [PathToDumpFile]\n", argv[0]);
    wprintf(L"EXAMPLE: \"%s\" c:\\Windows\\System32\\Winevt\\Logs\\Security.evtx Event/System[EventID=4624] c:\\Users\\%%username%%\\Downloads\n", argv[0]); // c:\Windows\System32\Winevt\Logs\Security.evtx Event/System[EventID=4624] c:\Users\%username%\Downloads
    wprintf(L"EXAMPLE: \"%s\" %%SystemRoot%%\\System32\\Winevt\\Logs\\Security.evtx Event/System[EventID=4624] c:\\Users\\%%username%%\\Downloads\n", argv[0]); // %SystemRoot%\System32\Winevt\Logs\Security.evtx Event/System[EventID=4624] c:\Users\%username%\Downloads
}

void ShowArguments(int argc, wchar_t* argv[])
{
    wprintf(L"\nShowArguments:\n");
    for (int i = 0; i < argc; i++)
    {
        wprintf(L"%d - \"%s\"\n", i, argv[i]);
    }
}

void ShowEnvironment()
{
    // todo: need to make a collector function, which will allow easier access to environment
    // todo: interpolate %EnvironmentVariables% inside path arguments used in this executable, for example %SystemRoot%
    // help: [ https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentstrings ] - get the environment in a block
    // help: [ https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getenvironmentvariable ] - envp is not an official way of retrieving environment variables
    // help: [ https://docs.microsoft.com/en-us/windows/win32/procthread/changing-environment-variables ] - best explanation of how it works
    // help: [ https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=registry ] - may potentially need to expand paths

    LPTSTR lpszVariable;
    LPTCH lpvEnv;

    wprintf(L"\nShowEnvironment:\n");

    // Get a pointer to the environment block.
    lpvEnv = GetEnvironmentStringsW();

    // If the returned pointer is NULL, exit.
    if (lpvEnv == NULL)
    {
        wprintf(L"GetEnvironmentStringsW failed (%d)\n", GetLastError());
        goto cleanup;
    }

    // Variable strings are separated by NULL byte, and the block is 
    // terminated by a NULL byte. 

    lpszVariable = (LPTSTR)lpvEnv;

    while (*lpszVariable)
    {
        wprintf(TEXT("%s\n"), lpszVariable);
        lpszVariable += lstrlen(lpszVariable) + 1;
    }

cleanup:
    if (NULL != lpvEnv)
        FreeEnvironmentStringsW(lpvEnv);
}
// **************************************** ****************************************


int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
#ifdef _DEBUG
    ShowArguments(argc, argv);
    RunTests(); // start by running some tests, only in debug mode
#endif // _DEBUG

    DWORD status = ERROR_SUCCESS;

    if (argc <= 3)
    {
        wprintf(L"Insufficient arguments provided!\n");
        ShowArguments(argc, argv);
        ShowEnvironment();
        PrintHelp(argv); 
        return ERROR_BAD_ARGUMENTS;
    }
    else if (argc > 4)
    {
        wprintf(L"Too many arguments provided!\n");
        ShowArguments(argc, argv);
        ShowEnvironment();
        PrintHelp(argv);
        return ERROR_BAD_ARGUMENTS;
    }

    LPWSTR pwsLogFile = NULL;
    pwsLogFile = InterpolateString(argv[1]);
    wprintf(L"InterpolateString(%s)=%s\n", argv[1], pwsLogFile); // todo: add a logging system with different levels depending on parameter or _debug define
    //free(pwsLogFile);

    LPWSTR pwsDumpFile = NULL;
    pwsDumpFile = ConstructFilename(argv[3]);
    wprintf(L"ConstructFilename(%s)=%s\n", argv[3], pwsDumpFile);
    //free(pwsDumpFile);

    // todo: instead of printing raw XML events to console, need to add a JSON export file and which fields to include, then do more complex processing in Python, or skip this part and do all processing in Python
    status = QueryEvents(pwsLogFile, argv[2], pwsDumpFile);

cleanup:
    free(pwsDumpFile);
    free(pwsLogFile);

    return status;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
