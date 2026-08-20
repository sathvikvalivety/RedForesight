import re
from typing import Dict

def sanitize_spl(value: str) -> str:
    # Remove any quotes, pipes, brackets, or backslashes to prevent SPL injection
    return re.sub(r'[\"\'\|\[\]\\]', '', value)

def host_activity_summary(host: str, window_minutes: int = 60) -> str:
    host = sanitize_spl(host)
    return (
        f'search index=botsv3 host="{host}" '
        f'| stats count by sourcetype '
        f'| sort - count'
    )

def auth_events_in_window(host: str, window_minutes: int = 30) -> str:
    host = sanitize_spl(host)
    return (
        f'search index=botsv3 host="{host}" '
        f'(EventCode=4624 OR EventCode=4625 OR EventCode=4648 OR '
        f'EventCode=4768 OR EventCode=4769 OR EventCode=4771) '
        f'| eval event_meaning=case('
        f'EventCode==4624, "Successful Logon", '
        f'EventCode==4625, "Failed Logon", '
        f'EventCode==4648, "Logon using Explicit Credentials", '
        f'EventCode==4768, "Kerberos TGT Request", '
        f'EventCode==4769, "Kerberos Service Ticket Request", '
        f'EventCode==4771, "Kerberos Pre-Auth Failed", '
        f'1=1, "Unknown") '
        f'| table _time, EventCode, event_meaning, user, src_ip, LogonType'
    )

def process_creation_events(host: str, window_minutes: int = 30) -> str:
    host = sanitize_spl(host)
    return (
        f'search index=botsv3 host="{host}" (EventCode=4688 OR EventCode=1) '
        f'| eval process=coalesce(NewProcessName, Image), '
        f'parent=coalesce(CreatorProcessName, ParentImage), '
        f'command_line=coalesce(CommandLine, ProcessCommandLine) '
        f'| table _time, EventCode, process, parent, command_line, user'
    )

def network_connections_from_host(host: str, window_minutes: int = 30, exclude_internal: bool = True) -> str:
    host = sanitize_spl(host)
    base_query = (
        f'search index=botsv3 host="{host}" EventCode=3 '
    )
    if exclude_internal:
        base_query += (
            f'| where NOT cidrmatch("10.0.0.0/8", DestinationIp) '
            f'AND NOT cidrmatch("172.16.0.0/12", DestinationIp) '
            f'AND NOT cidrmatch("192.168.0.0/16", DestinationIp) '
        )
    base_query += f'| table _time, DestinationIp, DestinationPort, Protocol, Image, user'
    return base_query

def asset_vulnerability_lookup(host: str) -> str:
    host = sanitize_spl(host)
    return (
        f'| inputlookup vulnerability_scores '
        f'| search host="{host}" '
        f'| table cvss_score, asset_criticality, owner, os_version'
    )

def build_context_queries(host: str, window_minutes: int = 30) -> Dict[str, str]:
    return {
        "host_summary": host_activity_summary(host, window_minutes),
        "auth_events": auth_events_in_window(host, window_minutes),
        "process_events": process_creation_events(host, window_minutes),
        "network_events": network_connections_from_host(host, window_minutes),
        "asset_lookup": asset_vulnerability_lookup(host)
    }

def generate_hunting_query(technique_id: str, technique_name: str, index: str = "botsv3") -> str:
    technique_id = sanitize_spl(technique_id)
    technique_name = sanitize_spl(technique_name)
    # Use wildcards to catch references to the ID or name in the raw logs
    # Build technique-specific hunting query based on the technique
    hunt_keywords = {
        "T1003": "EventCode=10 lsass",
        "T1059": "EventCode=4104 powershell",
        "T1566": "EventCode=1 winword.exe",
        "T1021": "EventCode=4624 LogonType",
        "T1190": "http exploit jndi",
        "T1486": "vssadmin encrypt",
        "T1574": "EventCode=7 dll load",
        "T1547": "EventCode=13 Run registry",
        "T1548": "fodhelper uac",
        "T1562": "Set-MpPreference Defender",
        "T1070": "wevtutil clear eventlog",
        "T1053": "schtasks create",
        "T1110": "EventCode=4625 failed",
        "T1558": "EventCode=4769 kerberos",
        "T1087": "net user domain",
        "T1046": "nmap scan port",
        "T1005": "robocopy file access",
        "T1071": "dns query TXT",
        "T1041": "https upload exfil",
        "T1048": "dns TXT exfil",
        "T1490": "vssadmin delete shadow",
        "T1529": "shutdown restart",
    }
    # Find matching keyword for this technique
    keyword = technique_name.lower().split()[0] if technique_name else "unknown"
    for tid, kw in hunt_keywords.items():
        if technique_id.startswith(tid):
            keyword = kw
            break
    return f'search index={index} ("*{technique_id}*" OR "*{technique_name}*" OR "*{keyword}*") | head 20'


