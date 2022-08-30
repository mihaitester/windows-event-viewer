`help: [ https://wordpress.com/support/markdown-quick-reference/ ]`

# Readme
I was thinking of trying to find security events that could indicate if my computer has been hacked and if there are weird things happening with my PC and one idea is to query the built-in windows events and see what is happening with the OS. However, using the `Windows Powershell` console or the default GUI called `Event viewer` does not offer enough flexibility to create special filters which can track such dubious activity. Hence the idea is to use the `Windows API` and dump reports or actively track events and showcase alerts and notifications when something weird is taking place.

Main difference from working with `Python` is that in `C/C++` developer has to keep track of variables and do memory management, and it takes a lot more volume of code to achieve same results, like for example working with timestamps and formatting of files. Also exception management and error recovery are way harder to do in `C/C++`. But once the code works and is debugged, it will run way faster and hopefully I can get some `timeit` wrapper done for `C/C++` to compare results.

# Usage windows-event-viewer.exe
> windows-event-viewer.exe `PathToEventFile` `XPathFormattedQuery` `PathToDumpFolder`
* `PathToEventFile` - example value `c:\Windows\System32\Winevt\Logs\Security.evtx` or `%SystemRoot%\System32\Winevt\Logs\Security.evtx`, however due to the caveat, its better to first copy the file outside `Windows` directory
* `XPathFormattedQuery` - XPath formatted query, for example `Event/System[EventID=4624]` which will return all events matching the `EventID`. For information visit `https://en.wikipedia.org/wiki/Event_Viewer` - which contains more about `Windows Event Viewer` and `XPath 1.0` limitations in the filter.
* `PathToDumpFile` - example value `c:\Users\%username%\Downloads`

For now the executable generates an `.xml` file containing the events from the requested event file and filtered by the `XPathFormattedQuery`. In the example given all events with `EventID=4624` will be dumped to the file. The file dumped will have a filename with the following structure `[PathToDumpFolder]\<Generated_Timestamp>_windows-event-viewer.xml`. The `<Generated_Timestamp>` is based on local time and has the following structure `YYYY-mm-dd_HH-MM-SS.sss`

### Caveats:
* In order to execute the script and have it not fail, you will need to run the `python windows-event-viewer.py` or `windows-event-viewer.exe` using an `Admin` console, otherwise the script will not be able to open the `Security.evtx` file.
    * Press `WinKey` + `X`, which opens the command popup, and then press `A` to open a `Windows Powershell` with admin rights. 
    * Then use, to navigate to current directory and execute the commandline from above, where `PathToScript` is the folder containing `windows-event-viewer.py` 
      > cd `PathToScript`

# Usage windows-event-viewer.py
> python windows-event-viewer.py `-f [PathToEventFile]`
- `-f [PathToEventFile]` - In order to avoid the caveat, first copy the `.evtx` log file you are interested in outside the default folder and into a folder that does not require admin rights.

For now the script goes through most of the `EventID`s described in the file `interesting_events_ids.json` over which it will invoke `windows-event-viewer.exe` and then it will process the `.xml.list` files and generate various `.json` files containing events that match queries simply constructed. Will have to enhance script by allowing for complex queries to be passed to the `windows-event-viewer.exe` which will process events faster than python processes string exports.

The idea overtime is to be able to define some rule sets for actions and then query the event files for matching events.

# Requirements
* `Visual Studio Community` - https://visualstudio.microsoft.com/vs/community/ - need to install the `Desktop development with C++` package - needed to import `Windows Event Viewer` solution and to compile and build the `windows-event-viewer.exe` tool which is used by the python script
* `Python` - https://www.python.org/downloads/windows/ - ideally get the latest version

# Optionals
* `Pycharm` - https://www.jetbrains.com/pycharm/download/#section=windows - can help a lot with debugging python script

# Similar projects
* https://pypi.org/project/python-evtx/ - should be able to extract events for processing directly in python - if the implementation relies on a lot of kernel calls than it is potentially slower than dumping `.xml` log and then processing text with python, will test this in the future

# Considerations
* `WARNING` - since I do not control the servers of the attached links, especially `# help: [ link ]` or `// help: [ link ]` those can be used by the server owners or `Internet Service Providers` to trackback developers, through logging of `IPAddress`, `OperatingSystem`, `Web Browser`