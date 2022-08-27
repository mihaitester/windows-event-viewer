`help: [ https://wordpress.com/support/markdown-quick-reference/ ]`

# Readme
I was thinking of trying to find security events that could indicate if my computer has been hacked and if there are weird things happening with my PC and one idea is to query the built-in windows events and see what is happening with the OS. However, using the `Windows Powershell` console or the default GUI called `Event viewer` does not offer enough flexibility to create special filters which can track such dubious activity. Hence the idea is to use the `Windows API` and dump reports or actively track events and showcase alerts and notifications when something weird is taking place.

Main difference from working with `Python` is that in `C/C++` developer has to keep track of variables and do memory management, and it takes a lot more volume of code to achieve same results, like for example working with timestamps and formatting of files. Also exception management and error recovery are way harder to do in `C/C++`. But once the code works and is debugged, it will run way faster and hopefully I can get some `timeit` wrapper done for `C/C++` to compare results.

# Usage
> windows-event-viewer.exe `PathToEventFile` `XPathFormattedQuery` `PathToDumpFolder`
* `PathToEventFile` - `c:\Windows\System32\Winevt\Logs\Security.evtx` or `%SystemRoot%\System32\Winevt\Logs\Security.evtx`
* `XPathFormattedQuery` - `Event/System[EventID=4624]`
* `PathToDumpFile` - `c:\Users\%username%\Downloads`

For now the executable generates an `.xml` file containing the events from the requested event file and filtered by the `XPathFormattedQuery`. In the example given all events with `EventID=4624` will be dumped to the file. The file dumped will have a filename with the following structure `[PathToDumpFolder]\<Generated_Timestamp>_windows-event-viewer.xml`. The `<Generated_Timestamp>` is based on local time and has the following structure `YYYY-mm-dd_HH-MM-SS.sss`

# Requirements
* `Visual Studio Community` - https://visualstudio.microsoft.com/vs/community/ - need to install the `Desktop development with C++` package - needed to import `Windows Event Viewer` solution and to compile and build the `windows-event-viewer.exe` tool which is used by the python script
* `Python` - https://www.python.org/downloads/windows/ - ideally get the latest version

# Optionals
* `Pycharm` - https://www.jetbrains.com/pycharm/download/#section=windows - can help a lot with debugging python script

# Similar projects
* https://pypi.org/project/python-evtx/ - should be able to extract events for processing directly in python - if the implementation relies on a lot of kernel calls than it is potentially slower than dumping `.xml` log and then processing text with python, will test this in the future

# Considerations
* `WARNING` - since I do not control the servers of the attached links, especially `# help: [ link ]` or `// help: [ link ]` those can be used by the server owners or `Internet Service Providers` to trackback developers, through logging of `IPAddress`, `OperatingSystem`, `Web Browser`