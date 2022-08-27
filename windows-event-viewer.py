import os
import glob
import subprocess

CONSOLE_ENCODING = "UTF-8"
FILE_ENCODING = "UTF-16-le"
NULL_WCHAR = '\x00'

def search_for_executable(path=os.path.abspath(os.path.dirname(__file__)), executable="windows-event-viewer.exe"):
    """
    search and return the path to the executable tool
    :param path:
    :param executable:
    :return:
    """
    executable_path = [x for x in glob.glob(os.path.join(path, "**/*"), recursive=True) if executable == os.path.basename(x)][0] # todo: instead of return first compiled executable, return the one that matches OS architecture
    return executable_path


def interpolate_path(path="", env=os.environ):
    interpolated_path = ""

    for item in path.split(os.sep):
        if '%' in item:
            interpolated_path += os.environ[item.lstrip('%').rstrip('%')]
        else:
            interpolated_path += item
        interpolated_path += os.sep

    return interpolated_path

def query_events(executable=search_for_executable(),
                 event_file=r"%SystemRoot%\System32\Winevt\Logs\Security.evtx",
                 filter="Event/System[EventID=4624]",
                 export_folder=r"%HomeDrive%\Users\%Username%\downloads"):
    """
    use the `windows-event-viewer.exe` to extract events from the windows log files
    :param event_file:
    :param filter:
    :param export_folder:
    :return:
    """
    args = [executable, event_file, filter, export_folder]
    proc = subprocess.run(args, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(proc.stdout.decode(CONSOLE_ENCODING))
    print(proc.stderr.decode(CONSOLE_ENCODING))

def getText(nodelist):
    rc = []
    for node in nodelist:
        if node.nodeType == node.TEXT_NODE:
            rc.append(node.nodeValue)
    return ''.join(rc)

if __name__ == "__main__":
    print(search_for_executable())

    extension = ".xml.list"

    export_folder = r"%HomeDrive%\Users\%Username%\downloads"
    interpolated_export_folder = interpolate_path(export_folder)

    # todo: capture files present before and after invocation, that way we can get the exact file that was generated
    files_before = glob.glob(os.path.join(interpolated_export_folder, "*" + extension))
    query_events(export_folder = export_folder)
    files_after = glob.glob(os.path.join(interpolated_export_folder, "*" + extension))

    generated_file = ""
    try:
        generated_file = [ x for x in files_after if x not in files_before ][0]
        print("Captured generated file [{}]".format(generated_file))
    except:
        print("Failed to generate [{}] export of requested events".format(extension))

    if "" == generated_file:
        generated_file = files_after[len(files_after) - 1] # note: added for debug, should remove afterwards

    # import xml.etree.ElementTree as ET

    from xml.dom.minidom import parse, parseString

    BOM = bytes([0xEF,0xBB, 0xBF])
    # todo: process the generated and collect multiple events for processing
    events = []
    # help: [ https://stackoverflow.com/questions/2746426/python-converting-wide-char-strings-from-a-binary-file-to-python-unicode-strin ]
    with open(generated_file, 'r', encoding=FILE_ENCODING) as readfile:
        content = readfile.read()

        # todo: add an exception handler that instead of printing useless column and line info, prints the actual string that caused issue, example [ "Data></EventData></Event>\x00<Event xmlns='http://sch" ]
        padding = 25
        line = 1
        column = 1784
        problem = content[line * column - padding: line * column + padding]
        # help: [ https://stackoverflow.com/questions/29533624/xml-parsing-error-junk-after-document-element-error-on-body-tag ] - if getting error "junk after ..." it means the xml document finished, dump file contains list of XML dumped objects, separated by NULL_WCHAR, and its not a fully valid XML document

        content = content.split(NULL_WCHAR) # note: it happens that `\x00` escapes inside the bytes stream, its due to how `PrintEvent` function in `windows-event-viewer.cpp` renders its output, it works out as we can use it to split content into list of event and parse sepparately

        # help: [ https://realpython.com/python-xml-parser/ ] - how to parse `.xml` string and use python objects to process
        # help: [ https://docs.python.org/3/library/xml.dom.minidom.html ]
        # help: [ https://mkyong.com/python/python-read-xml-file-dom-example/ ] - how to parse XML
        for item in content:
            xml_event = parseString(item)
            # xml_event.getElementsByTagName("EventID")[0].childNodes[0].nodeValue
            xml_eventid = xml_event.getElementsByTagName("EventID")[0].childNodes
            eventid = int(getText(xml_eventid))
            pass

        # todo: need to collect timestamps and processID with all process data -> track back which process and what command line was executing when an event was triggered

    pass # used for debugging