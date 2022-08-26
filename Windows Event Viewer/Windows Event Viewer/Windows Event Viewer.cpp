// Windows Event Viewer.cpp : This file contains the 'main' function. Program execution begins and ends there.
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

#pragma comment(lib, "wevtapi.lib")

#define ARRAY_SIZE 10
#define TIMEOUT 1000  // 1 second; Set and use in place of INFINITE in EvtNext call

//DWORD PrintResults(EVT_HANDLE hResults);
//DWORD PrintEvent(EVT_HANDLE hEvent); // Shown in the Rendering Events topic

DWORD PrintEvent(EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    LPWSTR pRenderedContent = NULL;

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

cleanup:

    if (pRenderedContent)
        free(pRenderedContent);

    return status;
}

// Enumerate all the events in the result set. 
DWORD PrintResults(EVT_HANDLE hResults)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hEvents[ARRAY_SIZE];
    DWORD dwReturned = 0;

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
            if (ERROR_SUCCESS == (status = PrintEvent(hEvents[i])))
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

    for (DWORD i = 0; i < dwReturned; i++)
    {
        if (NULL != hEvents[i])
            EvtClose(hEvents[i]);
    }

    return status;
}

DWORD QueryEvents(LPCWSTR pwsPath, LPCWSTR pwsQuery)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL;

    hResults = EvtQuery(NULL, pwsPath, pwsQuery, EvtQueryFilePath | EvtQueryReverseDirection);
    // hResults = EvtQuery(NULL, pwsPath, pwsQuery, EvtQueryChannelPath | EvtQueryReverseDirection);
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

    PrintResults(hResults);

cleanup:

    if (hResults)
        EvtClose(hResults);

    return status;

}

void PrintHelp(wchar_t* argv[])
{
    wprintf(L"\nPrintHelp:\n");
    wprintf(L"\"%s\" [PathToEventFile] [XPathFormattedQuery]\n", argv[0]);
    wprintf(L"EXAMPLE: \"%s\" c:\\Windows\\System32\\Winevt\\Logs\\Security.evtx Event/System[EventID=4624]\n", argv[0]); // c:\Windows\System32\Winevt\Logs\Security.evtx Event/System[EventID=4624]
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
    // help: [ https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentstrings ] - get the environment in a block
    // help: [ https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getenvironmentvariable ] - envp is not an official way of retrieving environment variables
    // help: [ https://docs.microsoft.com/en-us/windows/win32/procthread/changing-environment-variables ] - best explanation of how it works
    
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

int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
    const LPCWSTR pwsPath = L"c:\\Windows\\System32\\Winevt\\Logs\\Security.evtx"; // why cant use [ Microsoft-Windows-Security-Auditing ] // %SystemRoot%\System32\Winevt\Logs\Security.evtx
    const LPCWSTR pwsQuery = L"Event/System[EventID=4624]"; // why cant use [ Event/System[EventID=4672] ]

    if (argc <= 1)
    {
        wprintf(L"Insufficient arguments provided!\n");
        ShowArguments(argc, argv);
        ShowEnvironment();
        PrintHelp(argv); 
        return ERROR_BAD_ARGUMENTS;
    }
    else if (argc > 3)
    {
        wprintf(L"Too many arguments provided!\n");
        ShowArguments(argc, argv);
        ShowEnvironment();
        PrintHelp(argv);
        return ERROR_BAD_ARGUMENTS;
    }
    
    return QueryEvents(argv[1], argv[2]);

    // todo: instead of printing raw XML events to console, need to add a JSON export file and which fields to include, then do more complex processing in Python, or skip this part and do all processing in Python
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
