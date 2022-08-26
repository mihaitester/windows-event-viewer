// Windows Event Viewer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// help: [ https://docs.microsoft.com/en-us/windows/win32/wes/querying-for-events ]

#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")

#define ARRAY_SIZE 10
#define TIMEOUT 1000  // 1 second; Set and use in place of INFINITE in EvtNext call

DWORD PrintResults(EVT_HANDLE hResults);
DWORD PrintEvent(EVT_HANDLE hEvent); // Shown in the Rendering Events topic

int main(void)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL;
    const LPCWSTR pwsPath = L"<Name of the channel goes here>";
    const LPCWSTR pwsQuery = L"Event/System[EventID=4]";

    hResults = EvtQuery(NULL, pwsPath, pwsQuery, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (NULL == hResults)
    {
        status = GetLastError();

        if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
            wprintf(L"The channel was not found.\n");
        else if (ERROR_EVT_INVALID_QUERY == status)
            // You can call the EvtGetExtendedStatus function to try to get 
            // additional information as to what is wrong with the query.
            wprintf(L"The query is not valid.\n");
        else
            wprintf(L"EvtQuery failed with %lu.\n", status);

        goto cleanup;
    }

    //PrintResults(hResults);

cleanup:

    if (hResults)
        EvtClose(hResults);

    return 0;
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
