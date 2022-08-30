import os
import glob
import subprocess
import sys
from xml.dom.minidom import parseString as xml_parse_string
import json
import argparse
import logging
import time
import datetime

import xmltodict

# todo: add a config file and use those values from there instead of hardcoding here
CONSOLE_ENCODING = "UTF-8"
FILE_ENCODING = "UTF-16-le"
NULL_WCHAR = '\x00'


DEFAULT_EVENT_FILE = r"%SystemRoot%\System32\Winevt\Logs\Security.evtx"
DEFAULT_FILTER = "Event/System[EventID=4624]"
DUMP_EXPORT_FOLDER = r"%HomeDrive%\Users\%Username%\downloads"
DUMP_EXTENSION = ".xml.list"


DATE_FORMAT = "%Y-%m-%d"
DATETIME_FORMAT = "%Y-%m-%d_%H-%M-%S"
LOG_FORMATTER = logging.Formatter(fmt='%(asctime)s.%(msecs)03d %(message)s', datefmt=DATETIME_FORMAT)
LOGGER = logging.Logger(__file__)

def print_time(time):
    miliseconds = time * 1000 % 1000
    seconds = time % 60
    time /= 60
    minutes = time % 60
    time /= 60
    hours = time % 24
    time /= 24
    days = time
    return "%ddays %.2d:%.2d:%.2d.%.3d" % (days, hours, minutes, seconds, miliseconds)


def print_size(size):
    bytes = size % 1024
    size /= 1024
    kbytes = size % 1024
    size /= 1024
    mbytes = size % 1024
    size /= 1024
    gbytes = size % 1024
    size /= 1024
    tbytes = size
    return "%.2fTB %.2fGB %.2fMB %.2fKB %.2fB" % (tbytes, gbytes, mbytes, kbytes, bytes)


def timeit(f):
    """
    help: [ https://stackoverflow.com/questions/1622943/timeit-versus-timing-decorator ]
    :param f:
    :return:
    """
    def timed(*args, **kw):
        ts = time.time()
        LOGGER.debug('>>> func:[{}] started @ [{}]'.format(f.__name__, ts))
        result = f(*args, **kw)
        te = time.time()
        LOGGER.debug('<<< func:[{}] ended @ [{}]'.format(f.__name__, te))
        LOGGER.info('=== func:[{}] took: [{}]'.format(f.__name__, print_time(te - ts)))
        return result
    return timed


def search_for_executable(path=os.path.abspath(os.path.dirname(__file__)), executable="windows-event-viewer.exe"):
    """
    search and return the path to the executable tool
    :param path:
    :param executable:
    :return:
    """
    executable_path = [x for x in glob.glob(os.path.join(path, "**/*"), recursive=True) if executable == os.path.basename(x)][0] # todo: instead of return first compiled executable, return the one that matches OS architecture
    LOGGER.debug("Found executable [{}]".format(executable_path))
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


@timeit
def query_events(executable=search_for_executable(),
                 event_file=DEFAULT_EVENT_FILE,
                 filter=DEFAULT_FILTER,
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
    LOGGER.debug("STDOUT: " + proc.stdout.decode(CONSOLE_ENCODING))
    LOGGER.debug("STDERR: " + proc.stderr.decode(CONSOLE_ENCODING))


@timeit
def process_xml_events(xml_events=[]):
    events = []
    for item in xml_events:
        event = xmltodict.parse(item)
        events.append(event)
    return events


# todo: remove this dead code after implementing todos mentioned inside
# def process_xml_events_old(xml_events=[]):
#     events = []
#     # help: [ https://realpython.com/python-xml-parser/ ] - how to parse `.xml` string and use python objects to process
#     # help: [ https://docs.python.org/3/library/xml.dom.minidom.html ]
#     # help: [ https://mkyong.com/python/python-read-xml-file-dom-example/ ] - how to parse XML
#     for item in xml_events:
#         xml_event = xml_parse_string(item)
#         # xml_event.getElementsByTagName("EventID")[0].childNodes[0].nodeValue
#
#         # help: [ https://pypi.org/project/xmldict/ ] - could have done this faster with this external package
#         # note: this code can easily break as it is, meaning changes in windows events will break this code
#         system = {}
#         intkeys = [ 'EventID', 'Version', 'Level', 'Task', 'Opcode', 'EventRecordID' ]
#         for key in intkeys:
#             system[key] = int(xml_event.getElementsByTagName(key)[0].childNodes[0].nodeValue)
#
#         stringkeys = [ 'Keywords', 'Channel', 'Computer', 'Security' ]
#         for key in stringkeys:
#             try:
#                 system[key] = xml_event.getElementsByTagName("Keywords")[0].childNodes[0].nodeValue
#             except:
#                 # todo: print only in debug mode
#                 # print("Failed to extract value for key [{}] for item [{}]".format(key, item)) # note: only one event presented error
#                 system[key] = ""
#
#         execution_processid = xml_event.getElementsByTagName("Execution")[0].getAttribute("ProcessID")
#         execution_threadid = xml_event.getElementsByTagName("Execution")[0].getAttribute("ThreadID")
#         correlation_activityid = xml_event.getElementsByTagName("Correlation")[0].getAttribute("ActivityID")
#         timecreated_systemtime = xml_event.getElementsByTagName("TimeCreated")[0].getAttribute("SystemTime")
#         provider_name = xml_event.getElementsByTagName("Provider")[0].getAttribute("Name")
#         provider_guid = xml_event.getElementsByTagName("Provider")[0].getAttribute("Guid")
#
#         system.update({
#             'Execution': {
#                 'ProcessID': execution_processid,
#                 'ThreadID': execution_threadid
#             },
#             'Correlation': {
#                 'ActivityID': correlation_activityid
#             },
#             'TimeCreated': {
#                 'SystemTime': timecreated_systemtime
#             },
#             'Provider': {
#                 'Name': provider_name,
#                 'Guid': provider_guid
#             }
#         })
#
#         eventdata = {}
#
#         # todo: here is the problem, different events have different fieds in the EVENT_DATA structure, so need to figure out a mapping that can describe this
#         # SubjectUserSid
#         # SubjectUserName
#         # SubjectDomainName
#         # SubjectLogonId
#         # TargetName
#         # WindowsLive
#         # Type
#         # CountOfCredentialsReturned
#         # ReadOperation
#         # ReturnCode
#         # ProcessCreationTime
#         # ClientProcessId
#
#         for key in ['SubjectUserSid', 'SubjectUserName', 'SubjectDomainName', 'SubjectLogonId', 'TargetUserSid',
#                     'TargetUserName', 'TargetDomainName', 'TargetLogonId', 'LogonType', 'LogonProcessName',
#                     'AuthenticationPackageName', 'WorkstationName', 'LogonGuid', 'TransmittedServices', 'LmPackageName',
#                     'KeyLength', 'ProcessId', 'ProcessName', 'IpAddress', 'IpPort', 'ImpersonationLevel',
#                     'RestrictedAdminMode', 'TargetOutboundUserName', 'TargetOutboundDomainName', 'VirtualAccount',
#                     'TargetLinkedLogonId', 'ElevatedToken']:
#             try:
#                 eventdata[key] = [x for x in xml_event.getElementsByTagName("Data") if x.getAttribute("Name") == key][0].childNodes[0].nodeValue
#             except:
#                 # todo: print only in debug mode
#                 # print("Failed to extract value for key [{}] for item [{}]".format(key, item)) # note: only one event presented error
#                 eventdata[key] = ""
#
#         # todo: another big one, basically the meaning of some of the values in the logs, numbers are hard to understand by humans - need to create mappings of what values mean - this cannot be skipped with `xmltodict`
#         # LogonType:
#         # 2 - Interactive(logon at keyboard and screen of system)
#         # 3 - Network(i.e.connection to shared folder on this computer from elsewhere on network)
#         # 4 - Batch(i.e.scheduled task)
#         # 5 - Service(Service startup)
#         # 6 - ???
#         # 7 - Unlock(i.e.unnattended workstation with password protected screen saver)
#         # 8 - NetworkCleartext(Logon with credentials sent in the clear text.Most often indicates a logon to IIS with "basic authentication") See this article for more information.
#         # 9 - NewCredentials such as with RunAs or mapping a network drive with alternate credentials.This logon type does not seem to show up in any events.If you want to track users attempting to logon with alternate credentials see 4648.  MS says "A caller cloned its current token and specified new credentials for outbound connections. The new logon session has the same local identity, but uses different credentials for other network connections."
#         # 10 - RemoteInteractive(Terminal Services, Remote Desktop or Remote Assistance)
#         # 11 - CachedInteractive(logon with cached domain credentials such as when logging on to a laptop when away from the network)
#
#         event = {'System': system, 'EventData': eventdata}
#         events.append(event)
#
#     return events


def collect_events(event_file=DEFAULT_EVENT_FILE,
                   filter=DEFAULT_FILTER, # help: [ https://en.wikipedia.org/wiki/Event_Viewer ] - more about `Windows Event Viewer` and `XPath 1.0` limitations in the filter
                   export_folder=DUMP_EXPORT_FOLDER,
                   suffix=""):
    interpolated_export_folder = interpolate_path(DUMP_EXPORT_FOLDER)

    # strip illegal path characters from suffix
    # help: [ https://stackoverflow.com/questions/1976007/what-characters-are-forbidden-in-windows-and-linux-directory-names ]
    for ch_ill in '%<>:"/\\|?*':
        suffix = suffix.replace(ch_ill, "_")

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


@timeit
def load_interesting_event_ids(file="interesting_event_ids.json"):
    # help: [ https://www.manageengine.com/network-monitoring/Eventlog_Tutorial_Part_II.html ]
    # help: [ https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ ]
    # todo: its not enough to have the meaning of the event_ids, need to have some config file describing which events are targetted, and generate a log based on that meta-descriptor
    # todo: conduct analysis of events and generate an audit report based on hashmap assigning criticality of events to event_ids
    interesting_event_ids = []
    with open(file, "r") as readfile:
        interesting_event_ids = json.loads(readfile.read())
        LOGGER.info("Loaded [{}] event IDs from file".format(len(interesting_event_ids)))
    return interesting_event_ids


CACHED_EVENTS = {}
@timeit
def get_events_between_dates(content="Advapi",
                             start_date=datetime.datetime.now() - datetime.timedelta(days=7),
                             end_date=datetime.datetime.now(), # end_date = datetime.datetime.strptime("2022-08-30", DATE_FORMAT)
                             interesting_event_ids=load_interesting_event_ids(),
                             event_ids=[x for x in load_interesting_event_ids().keys()],
                             event_file = DEFAULT_EVENT_FILE,
                             suffix=""):
    LOGGER.info("Processing all events for specific content: [{}]".format(content))

    e_all = []
    # note: cache somehow all events instead of doing calls again over the files, basically allow multiple `get_events_between_dates` calls using in memory data
    if event_file not in CACHED_EVENTS.keys():
        for x in event_ids:
            e = collect_events(event_file=event_file,
                               filter="Event/System[EventID={}]".format(x),
                               suffix="-" + "-".join(interesting_event_ids[x].split(" ")))
            e_all.append(e)
        CACHED_EVENTS.update({event_file:e_all}) # cache all events regardless of content
        LOGGER.info("Cached events [{}] from [{}] taking up [{}].".format(len(CACHED_EVENTS[event_file]), event_file, print_size(sys.getsizeof(CACHED_EVENTS[event_file]))))
    else:
        e_all = CACHED_EVENTS[event_file]

    e_content = []
    for e in e_all:
        for y in e:
            if content != "":
                if content in str(y):
                    e_content.append(y)
                else:
                    pass
            else:
                # note: if content is not provided, then include all events
                e_content.append(y)

    e_dated = []
    for event in e_content:
        # help: [ https://www.digitalocean.com/community/tutorials/python-string-to-datetime-strptime ]
        # help: [ https://docs.python.org/3/library/datetime.html#datetime.datetime.strptime ]
        # data_string = "2022-08-24T10:08:18.371409200Z"
        # st = datetime.datetime.fromisoformat(data_string[:-4])
        # format_regex = "%Y-%m-%dT%H:%M:%S.%f"
        # t = time.strptime(data_string[:-4], format_regex)
        e_datetime = datetime.datetime.fromisoformat(event["Event"]["System"]["TimeCreated"]["@SystemTime"][:-4])
        if e_datetime >= start_date and e_datetime <= end_date:
            e_dated.append(event)
    with open(os.path.join(interpolate_path(DUMP_EXPORT_FOLDER),
                           datetime.datetime.now().strftime(DATETIME_FORMAT) + "-events-between-{}-and-{}".format(
                                   start_date.strftime(DATE_FORMAT), end_date.strftime(DATE_FORMAT)) + suffix + ".json"),
              "w") as writefile:
        writefile.write(json.dumps(e_dated, indent=4))

@timeit
def process_audit(event_file=DEFAULT_EVENT_FILE, interesting_event_ids=load_interesting_event_ids()):

    # 4649: "A replay attack was detected", # todo: how does windows actually identify replay attacks and does it actually do something or leaves user vulnerable to exploits

    # todo: append to the logs generated the meaning of the EventID that was filtered
    # todo: have a better way of collecting events and figuring out if penetration did take place -> for example chained events that describe malware actions
    auditlogscleared = [x for x in interesting_event_ids.keys() if "The audit log was cleared" in interesting_event_ids[x]][0]
    e_auditlogscleared = collect_events(event_file=event_file, filter="Event/System[EventID={}]".format(auditlogscleared))

    auditchanges = [x for x in interesting_event_ids.keys() if "System audit policy was changed" in interesting_event_ids[x]][0]
    e_auditchanges = collect_events(event_file=event_file, filter="Event/System[EventID={}]".format(auditchanges))

    logons = [x for x in interesting_event_ids.keys() if "An account was successfully logged on" in interesting_event_ids[x]][0]
    e_logons = collect_events(event_file=event_file, filter="Event/System[EventID={}]".format(logons), suffix="-"+"-".join(interesting_event_ids[logons].split(" ")))

    logouts = [x for x in interesting_event_ids.keys() if "An account was logged off" in interesting_event_ids[x]][0]
    e_logouts = collect_events(event_file=event_file, filter="Event/System[EventID={}]".format(logouts), suffix="-"+"-".join(interesting_event_ids[logouts].split(" ")))

    # collect multiple events in a single list, but it will generate different files
    # todo: need to be able to skip printing of files before processing is finished
    kerberos = [x for x in interesting_event_ids.keys() if "Kerberos" in interesting_event_ids[x]]
    LOGGER.info("Processing kerberos events: [{}]".format(kerberos))
    e_kerberos = []
    [ e_kerberos.extend(collect_events(event_file=event_file, filter="Event/System[EventID={}]".format(x), suffix="-"+"-".join(interesting_event_ids[x].split(" ")))) for x in kerberos ]

    firewall = [x for x in interesting_event_ids.keys() if "Firewall" in interesting_event_ids[x]]
    LOGGER.info("Processing firewall events: [{}]".format(firewall))
    e_firewall = []
    [ e_firewall.extend(collect_events(event_file=event_file, filter="Event/System[EventID={}]".format(x), suffix="-"+"-".join(interesting_event_ids[x].split(" ")))) for x in firewall ]

    ipsec = [x for x in interesting_event_ids.keys() if "IPsec" in interesting_event_ids[x]]
    LOGGER.info("Processing ipsec events: [{}]".format(ipsec))
    e_ipsec = []
    [ e_ipsec.extend(collect_events(event_file=event_file, filter="Event/System[EventID={}]".format(x), suffix="-" + "-".join(interesting_event_ids[x].split(" ")))) for x in ipsec ]

    crypto = [x for x in interesting_event_ids.keys() if "crypto" in interesting_event_ids[x]]
    LOGGER.info("Processing ipsec events: [{}]".format(crypto))
    e_crypto = []
    [ e_crypto.extend(collect_events(event_file=event_file, filter="Event/System[EventID={}]".format(x), suffix="-" + "-".join(interesting_event_ids[x].split(" ")))) for x in crypto ]

    # todo: provide some suffix to differentiate files and have easily accessible reports
    get_events_between_dates(content="", event_file=event_file, suffix="-all") # get all events
    get_events_between_dates(content="Advapi", event_file=event_file, suffix="-advapi") # get events with content "Advapi"


def menu():
    parser = argparse.ArgumentParser(description='Given `.evtx` files from Windows this script will analyze logs and showcase warnings and security issues that it finds based on some prepared rules.')

    parser.add_argument('-d', '--debug', choices=['critical', 'error', 'warning', 'info', 'debug', 'notset'],
                        default='info', required=False,
                        help='parameter indicating the level of logs to be shown on screen')
    parser.add_argument('-e', '--event_file', required=False,
                        help='parameter indicating a singular event file to be analyzed')
    # parser.add_argument('-c', '--clean', action="store_true", required=False,
    #                     help='parameter indicating that all files `.xml.list` and `.json` will be deleted before running script')

    arguments = parser.parse_args()

    # patch logging level to objects
    debug_name = arguments.debug
    debug_levels = {'critical': logging.CRITICAL, 'error': logging.ERROR, 'warning': logging.WARNING,
                    'info': logging.INFO, 'debug': logging.DEBUG, 'notset': logging.NOTSET}
    arguments.debug = debug_levels[arguments.debug]
    print("Using logging level [{}:{}]".format(debug_name, arguments.debug))

    return arguments

if __name__ == "__main__":
    args = menu()

    handler = logging.StreamHandler()
    handler.setFormatter(LOG_FORMATTER)
    handler.setLevel(args.debug)
    LOGGER.addHandler(handler)

    LOGGER.setLevel(args.debug)

    # todo: need use a service to collect timestamps and processID with all process data -> track back which process and what command line was executing when an event was triggered

    process_audit(args.event_file)

    pass # used for debugging