from typing import Dict

def host_activity_summary(host: str, window_minutes: int = 60) -> str:
    return (
        f'search index=* host="{host}" '
        f'| stats count by sourcetype '
        f'| sort - count'
    )

def auth_events_in_window(host: str, window_minutes: int = 30) -> str:
    return (
        f'search index=* host="{host}" '
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
    return (
        f'search index=* host="{host}" (EventCode=4688 OR EventCode=1) '
        f'| eval process=coalesce(NewProcessName, Image), '
        f'parent=coalesce(CreatorProcessName, ParentImage), '
        f'command_line=coalesce(CommandLine, ProcessCommandLine) '
        f'| table _time, EventCode, process, parent, command_line, user'
    )

def network_connections_from_host(host: str, window_minutes: int = 30, exclude_internal: bool = True) -> str:
    base_query = (
        f'search index=* host="{host}" EventCode=3 '
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
