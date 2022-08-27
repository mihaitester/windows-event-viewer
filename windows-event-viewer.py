import os
import glob
import subprocess

ENCODING = "UTF-8"

def search_for_executable(path=os.path.abspath(os.path.dirname(__file__)), executable="windows-event-viewer.exe"):
    """
    search and return the path to the executable tool
    :param path:
    :param executable:
    :return:
    """
    executable_path = [x for x in glob.glob(os.path.join(path, "**/*"), recursive=True) if executable == os.path.basename(x)][0] # todo: instead of return first compiled executable, return the one that matches OS architecture
    return executable_path

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
    print(proc.stdout.decode(ENCODING))
    print(proc.stderr.decode(ENCODING))

if __name__ == "__main__":
    print(search_for_executable())
    query_events()

    pass # used for debugging