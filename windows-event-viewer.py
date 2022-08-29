import os
import glob
import subprocess
from xml.dom.minidom import parseString as xml_parse_string
import json

# todo: add a config file and use those values from there instead of hardcoding here
CONSOLE_ENCODING = "UTF-8"
FILE_ENCODING = "UTF-16-le"
NULL_WCHAR = '\x00'
DUMP_EXTENSION = ".xml.list"
DUMP_EXPORT_FOLDER = r"%HomeDrive%\Users\%Username%\downloads"


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
                 export_folder=DUMP_EXPORT_FOLDER,
                 suffix=""):
    """
    use the `windows-event-viewer.exe` to extract events from the windows log files
    :param event_file:
    :param filter:
    :param export_folder:
    :return:
    """
    args = [executable, event_file, filter, export_folder, suffix]
    proc = subprocess.run(args, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # todo: print these only in debug mode
    # print(proc.stdout.decode(CONSOLE_ENCODING))
    # print(proc.stderr.decode(CONSOLE_ENCODING))


def process_xml_events(xml_events=[]):
    events = []
    # help: [ https://realpython.com/python-xml-parser/ ] - how to parse `.xml` string and use python objects to process
    # help: [ https://docs.python.org/3/library/xml.dom.minidom.html ]
    # help: [ https://mkyong.com/python/python-read-xml-file-dom-example/ ] - how to parse XML
    for item in xml_events:
        xml_event = xml_parse_string(item)
        # xml_event.getElementsByTagName("EventID")[0].childNodes[0].nodeValue

        # help: [ https://pypi.org/project/xmldict/ ] - could have done this faster with this external package
        # note: this code can easily break as it is, meaning changes in windows events will break this code
        system = {}
        intkeys = [ 'EventID', 'Version', 'Level', 'Task', 'Opcode', 'EventRecordID' ]
        for key in intkeys:
            system[key] = int(xml_event.getElementsByTagName(key)[0].childNodes[0].nodeValue)

        stringkeys = [ 'Keywords', 'Channel', 'Computer', 'Security' ]
        for key in stringkeys:
            try:
                system[key] = xml_event.getElementsByTagName("Keywords")[0].childNodes[0].nodeValue
            except:
                # todo: print only in debug mode
                # print("Failed to extract value for key [{}] for item [{}]".format(key, item)) # note: only one event presented error
                system[key] = ""

        execution_processid = xml_event.getElementsByTagName("Execution")[0].getAttribute("ProcessID")
        execution_threadid = xml_event.getElementsByTagName("Execution")[0].getAttribute("ThreadID")
        correlation_activityid = xml_event.getElementsByTagName("Correlation")[0].getAttribute("ActivityID")
        timecreated_systemtime = xml_event.getElementsByTagName("TimeCreated")[0].getAttribute("SystemTime")
        provider_name = xml_event.getElementsByTagName("Provider")[0].getAttribute("Name")
        provider_guid = xml_event.getElementsByTagName("Provider")[0].getAttribute("Guid")

        system.update({
            'Execution': {
                'ProcessID': execution_processid,
                'ThreadID': execution_threadid
            },
            'Correlation': {
                'ActivityID': correlation_activityid
            },
            'TimeCreated': {
                'SystemTime': timecreated_systemtime
            },
            'Provider': {
                'Name': provider_name,
                'Guid': provider_guid
            }
        })

        eventdata = {}

        # todo: here is the problem, different events have different fieds in the EVENT_DATA structure, so need to figure out a mapping that can describe this
        # SubjectUserSid
        # SubjectUserName
        # SubjectDomainName
        # SubjectLogonId
        # TargetName
        # WindowsLive
        # Type
        # CountOfCredentialsReturned
        # ReadOperation
        # ReturnCode
        # ProcessCreationTime
        # ClientProcessId

        for key in ['SubjectUserSid', 'SubjectUserName', 'SubjectDomainName', 'SubjectLogonId', 'TargetUserSid',
                    'TargetUserName', 'TargetDomainName', 'TargetLogonId', 'LogonType', 'LogonProcessName',
                    'AuthenticationPackageName', 'WorkstationName', 'LogonGuid', 'TransmittedServices', 'LmPackageName',
                    'KeyLength', 'ProcessId', 'ProcessName', 'IpAddress', 'IpPort', 'ImpersonationLevel',
                    'RestrictedAdminMode', 'TargetOutboundUserName', 'TargetOutboundDomainName', 'VirtualAccount',
                    'TargetLinkedLogonId', 'ElevatedToken']:
            try:
                eventdata[key] = [x for x in xml_event.getElementsByTagName("Data") if x.getAttribute("Name") == key][0].childNodes[0].nodeValue
            except:
                # todo: print only in debug mode
                # print("Failed to extract value for key [{}] for item [{}]".format(key, item)) # note: only one event presented error
                eventdata[key] = ""

        # todo: another big one, basically the meaning of some of the values in the logs, numbers are hard to understand by humans - need to create mappings of what values mean - this cannot be skipped with `xmltodict`
        # LogonType:
        # 2 - Interactive(logon at keyboard and screen of system)
        # 3 - Network(i.e.connection to shared folder on this computer from elsewhere on network)
        # 4 - Batch(i.e.scheduled task)
        # 5 - Service(Service startup)
        # 6 - ???
        # 7 - Unlock(i.e.unnattended workstation with password protected screen saver)
        # 8 - NetworkCleartext(Logon with credentials sent in the clear text.Most often indicates a logon to IIS with "basic authentication") See this article for more information.
        # 9 - NewCredentials such as with RunAs or mapping a network drive with alternate credentials.This logon type does not seem to show up in any events.If you want to track users attempting to logon with alternate credentials see 4648.  MS says "A caller cloned its current token and specified new credentials for outbound connections. The new logon session has the same local identity, but uses different credentials for other network connections."
        # 10 - RemoteInteractive(Terminal Services, Remote Desktop or Remote Assistance)
        # 11 - CachedInteractive(logon with cached domain credentials such as when logging on to a laptop when away from the network)

        event = {'System': system, 'EventData': eventdata}
        events.append(event)

    return events


def collect_events(event_file=r"%SystemRoot%\System32\Winevt\Logs\Security.evtx",
                   filter="Event/System[EventID=4624]", # help: [ https://en.wikipedia.org/wiki/Event_Viewer ] - more about `Windows Event Viewer` and `XPath 1.0` limitations in the filter
                   export_folder=DUMP_EXPORT_FOLDER,
                   suffix=""):
    print(search_for_executable())
    interpolated_export_folder = interpolate_path(DUMP_EXPORT_FOLDER)

    # todo: capture files present before and after invocation, that way we can get the exact file that was generated
    files_before = glob.glob(os.path.join(interpolated_export_folder, "*" + DUMP_EXTENSION))
    query_events(event_file=event_file, filter=filter, export_folder=export_folder, suffix=suffix)
    files_after = glob.glob(os.path.join(interpolated_export_folder, "*" + DUMP_EXTENSION))

    generated_file = ""
    try:
        generated_file = [x for x in files_after if x not in files_before][0]
        print("Captured generated file [{}]".format(generated_file))
    except:
        print("Failed to generate [{}] export of requested events [{}]".format(DUMP_EXTENSION, filter))
        # generated_file = files_after[len(files_after) - 1]  # todo: added for debug, should remove afterwards
        return []

    # todo: process multiple generated files and collect different classes of events for processing
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

        content = content.split(NULL_WCHAR)  # note: it happens that `\x00` escapes inside the bytes stream, its due to how `PrintEvent` function in `windows-event-viewer.cpp` renders its output, it works out as we can use it to split content into list of event and parse sepparately
        content = content[:-1]  # note: remove the last item as it is empty

        events = process_xml_events(content)

    if len(events):
        with open(generated_file.replace(DUMP_EXTENSION, '') + ".json", 'w') as writefile:
            writefile.write(json.dumps(events, indent=4))
    else:
        print("Failed to find events for filter [{}]".format(filter))

    return events

if __name__ == "__main__":
    # todo: need use a service to collect timestamps and processID with all process data -> track back which process and what command line was executing when an event was triggered

    # help: [ https://www.manageengine.com/network-monitoring/Eventlog_Tutorial_Part_II.html ]
    # help: [ https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ ]
    # todo: its not enough to have the meaning of the event_ids, need to have some config file describing which events are targetted, and generate a log based on that meta-descriptor
    # todo: conduct analysis of events and generate an audit report based on hashmap assigning criticality of events to event_ids
    interesting_event_ids = []
    with open("interesting_event_ids.json", "r") as readfile:
        interesting_event_ids = json.loads(readfile.read())


    # interestingeventids = {1100: "The event logging service has shut down",
    #                        1101: "Audit events have been dropped by the transport.",
    #                        1102: "The audit log was cleared",
    #                        1104: "The security Log is now full",
    #                        1108: "The event logging service encountered an error",
    #                        4611: "A trusted logon process has been registered with the Local Security Authority",
    #                        4612: "Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits.",
    #                        4616: "The system time was changed.",
    #                        4608: "4608 to 4612 System Events", 4612: "Audit Logs Cleared",
    #                        4624: "An account was successfully logged on", 4625: "Logon Failures",
    #                        4626: "User / Device claims information",
    #                        4627: "Group membership information.",
    #                        4634: "An account was logged off",
    #                        4646: "IKE DoS - prevention mode started",
    #                        4647: "User initiated logoff",
    #                        4648: "A logon was attempted using explicit credentials",
    #                        4649: "A replay attack was detected", # todo: how does windows actually identify replay attacks and does it actually do something or leaves user vulnerable to exploits
    #                        4650: "An IPsec Main Mode security association was established",
    #                        4651: "An IPsec Main Mode security association was established",
    #                        4652: "An IPsec Main Mode negotiation failed",
    #                        4653: "An IPsec Main Mode negotiation failed",
    #                        4654: "An IPsec Quick Mode negotiation failed",
    #                        4655: "An IPsec Main Mode security association ended",
    #                        4656: "A handle to an object was requested",
    #                        4656: "Object Access",
    #                        4656: "A handle to an object was requested", # objects are usually files, hence FILE_OPEN -> over 90% of the time
    #                        4657: "A registry value was modified",
    #                        4658: "The handle to an object was closed", # objects are usually files, hence FILE_CLOSE -> over 90% of the time
    #                        4659: "A handle to an object was requested with intent to delete",
    #                        4660: "An object was deleted", # objects are usually files, hence FILE_DELETE
    #                        4661: "A handle to an object was requested",
    #                        4658: "(4658 to 4664)",
    #                        4719: "Audit Policy Changes", 4720: "User Account Changes", 4722: "", 4723: "", 4724: "",
    #                        4725: "", 4726: "", 4738: "", 4740: "", 4727: "", 4728: "",
    #                        4729: "", 4730: "", 4731: "", 4732: "", 4733: "", 4734: "", 4735: "", 4736: "", 4737: "",
    #                        4739: "4739 to 4762", 4768: "Successful User Account Validation",
    #                        4776: "Successful User Account Validation", 4771: "Failed User Account Validation",
    #                        4777: "Failed User Account Validation", 4778: "Host Session Status",
    #                        4779: "Host Session Status"}

    # todo: append to the logs generated the meaning of the EventID that was filtered
    # todo: have a better way of collecting events and figuring out if penetration did take place -> for example chained events that describe malware actions
    auditlogscleared = [x for x in interesting_event_ids.keys() if "The audit log was cleared" in interesting_event_ids[x]][0]
    e_auditlogscleared = collect_events(filter="Event/System[EventID={}]".format(auditlogscleared))

    auditchanges = [x for x in interesting_event_ids.keys() if "System audit policy was changed" in interesting_event_ids[x]][0]
    e_auditchanges = collect_events(filter="Event/System[EventID={}]".format(auditchanges))

    logons = [x for x in interesting_event_ids.keys() if "An account was successfully logged on" in interesting_event_ids[x]][0]
    e_logons = collect_events(filter="Event/System[EventID={}]".format(logons), suffix="-"+"-".join(interesting_event_ids[logons].split(" ")))

    logouts = [x for x in interesting_event_ids.keys() if "An account was logged off" in interesting_event_ids[x]][0]
    e_logouts = collect_events(filter="Event/System[EventID={}]".format(logouts), suffix="-"+"-".join(interesting_event_ids[logouts].split(" ")))

    # collect multiple events in a single list, but it will generate different files
    # todo: need to be able to skip printing of files before processing is finished
    kerberos = [x for x in interesting_event_ids.keys() if "Kerberos" in interesting_event_ids[x]]
    print("Processing kerberos events: [{}]".format(kerberos))
    e_kerberos = []
    [ e_kerberos.extend(collect_events(filter="Event/System[EventID={}]".format(x), suffix="-"+"-".join(interesting_event_ids[x].split(" ")))) for x in kerberos ]

    firewall = [x for x in interesting_event_ids.keys() if "Firewall" in interesting_event_ids[x]]
    print("Processing firewall events: [{}]".format(firewall))
    e_firewall = []
    [ e_firewall.extend(collect_events(filter="Event/System[EventID={}]".format(x), suffix="-"+"-".join(interesting_event_ids[x].split(" ")))) for x in firewall ]

    ipsec = [x for x in interesting_event_ids.keys() if "IPsec" in interesting_event_ids[x]]
    print("Processing ipsec events: [{}]".format(ipsec))
    e_ipsec = []
    [ e_ipsec.extend(collect_events(filter="Event/System[EventID={}]".format(x), suffix="-" + "-".join(interesting_event_ids[x].split(" ")))) for x in ipsec ]

    crypto = [x for x in interesting_event_ids.keys() if "crypto" in interesting_event_ids[x]]
    print("Processing ipsec events: [{}]".format(crypto))
    e_crypto = []
    [e_crypto.extend(collect_events(filter="Event/System[EventID={}]".format(x), suffix="-" + "-".join(interesting_event_ids[x].split(" ")))) for x in crypto ]

    all = [ x for x in interesting_event_ids.keys() ]
    content = "Advapi"
    print("Processing all events for specific content: [{}]".format(content))
    e_all = []
    for x in all:
        e = collect_events(filter="Event/System[EventID={}]".format(x), suffix="-" + "-".join(interesting_event_ids[x].split(" ")))
        for y in e:
            if content in y:
                e_all.append(y)

    pass # used for debugging