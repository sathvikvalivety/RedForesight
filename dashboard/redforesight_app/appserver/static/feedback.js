require([
    "jquery",
    "splunkjs/mvc",
    "splunkjs/mvc/simplexml/ready!"
], function($, mvc) {
    console.log("RedForesight feedback.js loaded");

    var apiHost = window.location.hostname || "127.0.0.1";
    var apiBaseUrl = "http://" + apiHost + ":8080/api/v1";
    var apiKeyDefault = "redforesight_demo_key_2026";

    function getApiKey() {
        var key = sessionStorage.getItem("redforesight_api_key");
        if (!key) {
            key = apiKeyDefault;
            sessionStorage.setItem("redforesight_api_key", key);
        }
        return key || "";
    }

    function status(msg, color) {
        $("#rf_trigger_status,#rf_feedback_status").css("color", color || "#aeb8fe").text(msg);
    }

    function fetchHealth() {
        $.ajax({
            url: apiBaseUrl.replace("/api/v1","") + "/health",
            type: "GET",
            success: function(data) {
                $("#live_episode_count").text(data.episode_count || 0);
            },
            error: function() { console.log("health fetch failed"); }
        });
    }
    setTimeout(fetchHealth, 1000);
    setInterval(fetchHealth, 5000);

    function eventToTactic(et) {
        var map = {"initial_access_attempt":"Initial Access","supply_chain_compromise":"Initial Access","trusted_relationship_abuse":"Initial Access","account_manipulation":"Persistence","execution_attempt":"Execution","persistence_attempt":"Persistence","privilege_escalation_attempt":"Privilege Escalation","defense_evasion_attempt":"Defense Evasion","credential_access_attempt":"Credential Access","discovery_attempt":"Discovery","lateral_movement_attempt":"Lateral Movement","collection_attempt":"Collection","c2_communication":"Command and Control","exfiltration_attempt":"Exfiltration","impact_attempt":"Impact","recon_attempt":"Reconnaissance"};
        return map[et] || "Other";
    }

    var SCENARIOS = {
        // ---- Initial Access ----
        t1566_001: { event_type: "initial_access_attempt", sev: "critical", host: "CORP-WS-07", source_ip: "10.0.0.5", raw: "Phishing email with malicious macro-laden Office document Invoice_Urgent.docm opened by user. WINWORD.EXE spawned powershell.exe with encoded base64 payload. Macro executed VBA shell function to download second-stage payload from remote C2. Parent process chain: outlook.exe to winword.exe to powershell.exe. This is T1566.001 Spearphishing Attachment with T1059.001 PowerShell execution." },
        t1566_002: { event_type: "initial_access_attempt", sev: "high", host: "WIN-DESKTOP-05", source_ip: "10.0.3.10", raw: "Spearphishing link clicked by user. Browser redirected to malicious URL hosting exploit kit. Suspicious JavaScript execution detected in Edge browser process msedge.exe. URL executed obfuscated shellcode via ArrayBuffer and WScript.Shell ActiveX object. User reported the email as suspicious after browser displayed fake Adobe Flash update prompt." },
        t1190: { event_type: "initial_access_attempt", sev: "critical", host: "DESKTOP-F4A2B1", source_ip: "10.0.1.42", raw: "Exploit attempt against public-facing web server. Apache access log shows CVE-2021-44228 Log4Shell JNDI lookup payload in HTTP User-Agent header. Tomcat process java.exe made outbound LDAP connection to attacker-controlled server. This is T1190 Exploit Public-Facing Application targeting unpatched Log4j library." },
        t1078: { event_type: "initial_access_attempt", sev: "high", host: "CORP-WS-07", source_ip: "194.165.12.85", raw: "Valid account authentication observed from anomalous geographic IP. Admin account jsmith logged in from Tor exit node. No prior authentication history from this ASN. Azure AD sign-in log shows unusual location and impossible travel detected - prior sign-in from New York 2 minutes earlier. This is T1078 Valid Accounts technique." },
        t1133: { event_type: "initial_access_attempt", sev: "high", host: "CORP-WS-07", source_ip: "45.155.205.233", raw: "External remote services abuse. VPN gateway logged successful authentication for service account svc_backup from new device fingerprint. No MFA challenge issued due to legacy VPN configuration bypassing conditional access policy. Session established from anomalous IP, lasted 4 hours, 3.2GB data transferred. This is T1133 External Remote Services." },
        t1195: { event_type: "supply_chain_compromise", sev: "critical", host: "ENG-WS-01", source_ip: "10.0.0.12", raw: "Compromised software supply chain. npm package found to contain postinstall script downloading payload from attacker server. Detected during CI pipeline scan - package.json modified by external contributor to include malicious install hook. This is T1195 Supply Chain Compromise targeting developer build pipeline." },
        t1199: { event_type: "trusted_relationship_abuse", sev: "high", host: "O365-SHAREPOINT", source_ip: "10.0.0.45", raw: "Trusted relationship abuse. Managed service provider account authenticated to customer Azure tenant via partner center. Performed mass Mailbox permission changes outside business hours - granted FullAccess to 47 mailboxes for newly created service principal. This is T1199 Trusted Relationship exploiting MSP access." },
        // ---- Execution ----
        t1059_001: { event_type: "execution_attempt", sev: "high", host: "WIN-DESKTOP-12", source_ip: "185.220.101.45", raw: "PowerShell execution detected. EventCode 4104 ScriptBlock logging captured encoded PowerShell command using IEX and WebClient.DownloadString to fetch payload from remote C2 server. Script included reflective PE injection and AMSI bypass via System.Reflection.Assembly.Load. Executed by non-admin user from temp directory. This is T1059.001 PowerShell." },
        t1059_003: { event_type: "execution_attempt", sev: "high", host: "BSTOLL-L", source_ip: "172.16.1.10", raw: "Windows Command Shell execution. cmd.exe spawned by unusual parent process wscript.exe executing net user backdoor creation and localgroup administrators addition. WScript launched from VBS file in startup folder. This is T1059.003 Windows Command Shell with T1136.001 Create Account." },
        t1059_004: { event_type: "execution_attempt", sev: "high", host: "CORP-WS-07", source_ip: "91.240.118.20", raw: "Unix shell execution via SSH. Auth log shows root login from anomalous IP via SSH key authentication. Followed by execution of chmod and binary launch in temp directory. Binary identified as XMRig cryptocurrency miner connecting to mining pool. This is T1059.004 Unix Shell." },
        t1059_006: { event_type: "execution_attempt", sev: "high", host: "CORP-WS-31", source_ip: "172.16.1.10", raw: "Python execution abuse. python.exe spawned by Excel macro executing urllib.request.urlopen to fetch second-stage payload from C2 server. Python script used ctypes to inject shellcode into explorer.exe process. This is T1059.006 Python." },
        t1204_002: { event_type: "execution_attempt", sev: "high", host: "DESKTOP-K7M3X9", source_ip: "10.0.3.10", raw: "User execution of malicious file. RegSvr32.exe registered DLL from temp directory using Squiblydoo technique with scripting engine COM object abuse for proxy execution bypassing AppLocker. This is T1204.002 Regsvr32." },
        t1106: { event_type: "execution_attempt", sev: "high", host: "DESKTOP-K7M3X9", source_ip: "45.155.205.233", raw: "Native API execution. Direct syscall to NtAllocateVirtualMemory detected via EDR, bypassing userland API hooks. Process hollowing of svchost.exe with Cobalt Strike beacon. NtUnmapViewOfSection and NtWriteVirtualMemory called in sequence. This is T1106 Native API for process injection." },
        // ---- Persistence ----
        t1098_001: { event_type: "account_manipulation", sev: "high", host: "AZURE-AD-SYNC", source_ip: "10.0.3.10", raw: "Additional cloud credentials. Azure AD audit log shows new service principal created by compromised admin account with API permissions Mail.ReadWrite, Files.Read.All, and Directory.ReadWrite.All. Certificate-based authentication configured with self-signed cert valid for 2 years. This is T1098.001 Additional Cloud Credentials for persistence." },
        t1547_001: { event_type: "persistence_attempt", sev: "high", host: "CORP-FILE-01", source_ip: "10.0.0.5", raw: "Registry Run key persistence. HKCU Software Microsoft Windows CurrentVersion Run UpdateService set to executable in Users Public directory. Registry key created by non-standard process at 02:33 AM. Executable hash matches known Cobalt Strike beacon. This is T1547.001 Registry Run Keys for persistence." },
        t1136_001: { event_type: "persistence_attempt", sev: "high", host: "CORP-WS-12", source_ip: "192.168.1.100", raw: "Create local account for persistence. net.exe created new local user svc_update with password and added to Administrators group. Executed from PowerShell running as SYSTEM. Account created at 03:15 AM, no prior user creation history. This is T1136.001 Local Account persistence." },
        t1543_002: { event_type: "persistence_attempt", sev: "high", host: "CORP-FILE-01", source_ip: "10.0.3.55", raw: "Service installation for persistence. New Windows service WindowsTelemetry created with binary path in ProgramData directory, configured for auto-start with delayed trigger. Service signed by non-Microsoft publisher. sc.exe create used from elevated cmd.exe. This is T1543.002 Windows Service persistence." },
        t1053_005: { event_type: "persistence_attempt", sev: "medium", host: "CORP-WS-12", source_ip: "10.0.2.33", raw: "Scheduled task created for persistence. schtasks create task SystemUpdate triggering executable in Users Public on every user logon with SYSTEM privileges. Created by user with no prior task creation history. This is T1053.005 Scheduled Task persistence." },
        t1547_009: { event_type: "persistence_attempt", sev: "high", host: "CORP-FILE-01", source_ip: "10.0.1.25", raw: "Authentication package persistence. Custom SSP dll loaded via LSA Security Packages registry value. DLL intercepts all authentication attempts, logging credentials in plaintext. Reboot required for activation. This is T1547.009 Authentication Package persistence." },
        t1574_001: { event_type: "persistence_attempt", sev: "high", host: "CORP-DC-01", source_ip: "192.168.1.45", raw: "DLL search order hijacking for persistence. Legitimate application loaded malicious version.dll from same directory instead of System32. Executed on every app launch. DLL hooks exported functions to load Cobalt Strike beacon in background. This is T1574.001 DLL Search Order Hijacking." },
        t1546_003: { event_type: "persistence_attempt", sev: "medium", host: "CORP-DC-01", source_ip: "10.2.5.14", raw: "WMI event subscription persistence. EventFilter SystemHealthCheck with CommandLineEventConsumer executing encoded PowerShell on timer every 300 seconds. WMI repository modified at 01:45 AM. Encoded payload downloads beacon from C2. This is T1546.003 WMI Event Subscription persistence." },
        // ---- Privilege Escalation ----
        t1548_002: { event_type: "privilege_escalation_attempt", sev: "high", host: "CORP-SQL-01", source_ip: "185.220.101.45", raw: "UAC bypass detected. fodhelper.exe launched with elevated privileges. Registry key ms-settings Shell Open command modified to point to custom executable. Auto-elevate set to 1. Fodhelper runs elevated and executes hijacked command. This is T1548.002 Bypass User Account Control." },
        t1068: { event_type: "privilege_escalation_attempt", sev: "critical", host: "CORP-SQL-01", source_ip: "10.0.0.12", raw: "Exploitation for privilege escalation. RoguePotato exploit detected. DCOM activation abuse leveraging SeImpersonatePrivilege. Printspooler service pipe impersonation to gain SYSTEM token. Process running as service account escalated to NT AUTHORITY SYSTEM. This is T1068 Exploitation for Privilege Escalation." },
        t1078_003: { event_type: "privilege_escalation_attempt", sev: "high", host: "CORP-APP-01", source_ip: "172.16.1.10", raw: "Local accounts privilege escalation. Compromised user account added to local Administrators group via net localgroup. Executed from PowerShell running as SYSTEM via PsExec. Account now has full local admin. This is T1078.003 Local Accounts privilege escalation." },
        t1134: { event_type: "privilege_escalation_attempt", sev: "high", host: "CORP-DC-01", source_ip: "192.168.1.45", raw: "Access token manipulation. Token theft and impersonation detected. Duplicate token from winlogon.exe used to create process with SYSTEM privileges via CreateProcessWithTokenW. Process now running with SYSTEM token. This is T1134 Access Token Manipulation." },
        t1574_011: { event_type: "privilege_escalation_attempt", sev: "high", host: "CORP-DC-01", source_ip: "172.16.1.10", raw: "DLL side-loading for privilege escalation. Legitimate binary sigverif.exe loaded malicious cryptbase.dll from current directory instead of System32. DLL hooks CreateProcessW to spawn elevated process. Signed binary abuse bypasses AppLocker and SmartScreen. This is T1574.011 DLL Side-Loading." },
        // ---- Defense Evasion ----
        t1027: { event_type: "defense_evasion_attempt", sev: "high", host: "CORP-WS-31", source_ip: "91.240.118.20", raw: "Obfuscated files or information. PowerShell script with heavy obfuscation detected: base64 encoded strings, variable name randomization, string concatenation to avoid signatures. Script content uses multiple layers of encoding including XOR. This is T1027 Obfuscated Files or Information." },
        t1140: { event_type: "defense_evasion_attempt", sev: "high", host: "CORP-DC-01", source_ip: "10.2.5.14", raw: "Deobfuscate or decode files. certutil.exe used to decode base64 payload to executable. Unusual usage of legit admin tool certutil for file decoding. Decoded file is Cobalt Strike beacon executable. This is T1140 Deobfuscate or Decode Files." },
        t1036_005: { event_type: "defense_evasion_attempt", sev: "medium", host: "CORP-DC-01", source_ip: "10.0.2.33", raw: "Masquerading. Process renamed to match legitimate service: svchost.exe running from Users Public instead of Windows System32. Detected via image path mismatch. Process name matches legitimate svchost but binary is unsigned. This is T1036.005 Match Legitimate Name." },
        t1562_001: { event_type: "defense_evasion_attempt", sev: "critical", host: "BSTOLL-L", source_ip: "10.0.0.12", raw: "Disable tools. Windows Defender real-time protection disabled via Set-MpPreference DisableRealtimeMonitoring. Executed by non-admin user via UAC bypass. Defender service disabled for 4 hours. Malware downloaded and executed during disabled window. This is T1562.001 Disable or Modify Tools." },
        t1562_002: { event_type: "defense_evasion_attempt", sev: "critical", host: "CORP-WS-22", source_ip: "10.1.1.5", raw: "Disable Windows event logging. EventLog service stopped via sc stop eventlog. Followed by clearing of Security event log via wevtutil cl Security. All audit events from 02:00-04:00 lost. Detected via gap in event stream. This is T1562.002 Disable Windows Event Logging." },
        t1070_004: { event_type: "defense_evasion_attempt", sev: "high", host: "BSTOLL-L", source_ip: "10.0.3.10", raw: "File deletion for cleanup. Evidence of post-exploitation cleanup: del and rmdir executed after credential exfiltration. Sdelete.exe used to securely wipe free space. This is T1070.004 File Deletion." },
        t1218_001: { event_type: "defense_evasion_attempt", sev: "medium", host: "BSTOLL-L", source_ip: "192.168.1.45", raw: "LOLBIN execution. rundll32.exe used to execute JavaScript payload via RunHTMLApplication. Proxy execution bypassing application whitelisting. JavaScript downloaded and executed second-stage payload. This is T1218.001 Rundll32." },
        // ---- Credential Access ----
        t1003_001: { event_type: "credential_access_attempt", sev: "critical", host: "CORP-DC-02", source_ip: "192.168.2.25", raw: "LSASS memory access. Process rundll32.exe accessed lsass.exe memory with GrantedAccess 0x1010. This access mask is consistent with credential dumping tools including Mimikatz. Source host BSTOLL-L. Sysmon EventCode 10 captured the process access. Parent process cmd.exe running as SYSTEM. This is T1003.001 LSASS Memory." },
        t1003_002: { event_type: "credential_access_attempt", sev: "critical", host: "CORP-DC-02", source_ip: "10.0.2.18", raw: "Security Account Manager dump. Registry hive SAM accessed via reg save to file in Users Public. Followed by SYSTEM and SECURITY hive extraction for offline password cracking. Executed from elevated cmd.exe at 03:12 AM. This is T1003.002 Security Account Manager." },
        t1003_006: { event_type: "credential_access_attempt", sev: "critical", host: "CORP-DC-02", source_ip: "10.2.5.14", raw: "DCSync attack. LSASS.exe processed DRSUAPI replication request from non-DC host. User account with Replicating Directory Changes permission abused to extract all domain password hashes. 347 user hashes exfiltrated. This is T1003.006 DCSync." },
        t1110_002: { event_type: "credential_access_attempt", sev: "high", host: "CORP-DC-01", source_ip: "194.165.12.85", raw: "Password guessing. 347 failed Kerberos pre-authentication events (EventCode 4771) in 5 minutes against service account. Brute-force pattern with 0.5s intervals. Account lockout policy prevented success. This is T1110.002 Password Cracking." },
        t1110_003: { event_type: "credential_access_attempt", sev: "high", host: "CORP-DC-02", source_ip: "194.165.12.85", raw: "Password spraying. 89 failed authentication events across 89 different user accounts in 2 minutes from single source IP. Single password attempted against all accounts. No account lockout due to distributed targets. This is T1110.003 Password Spraying." },
        t1056: { event_type: "credential_access_attempt", sev: "high", host: "BSTOLL-L", source_ip: "185.220.101.45", raw: "Input capture. Keylogger module detected injecting into explorer.exe. Hooking SetWindowsHookEx WH_KEYBOARD_LL. Logging keystrokes to file. Captured credentials for domain admin account. This is T1056 Input Capture." },
        t1558: { event_type: "credential_access_attempt", sev: "high", host: "CORP-DC-01", source_ip: "172.16.1.10", raw: "Steal or forge Kerberos tickets. Kerberoasting detected. Requests for TGS for SPN MSSQLSvc. Ticket encrypted with RC4-HMAC. Offline cracking of service account password likely. EventCode 4769 shows unusual ticket request pattern. This is T1558 Steal or Forge Kerberos Tickets." },
        // ---- Discovery ----
        t1087_001: { event_type: "discovery_attempt", sev: "low", host: "CORP-WS-12", source_ip: "10.0.2.18", raw: "Account discovery. net user domain and net group Domain Admins domain executed by non-admin user. Enumerating all domain accounts and privileged groups. Followed by net localgroup administrators on local host. This is T1087.001 Local Account discovery." },
        t1018: { event_type: "discovery_attempt", sev: "low", host: "CORP-WS-22", source_ip: "192.168.1.45", raw: "Remote system discovery. nmap scan detected: scanning entire internal subnet for SMB, RDP, WinRM services. 47 hosts found alive. Executed from compromised host BSTOLL-L. This is T1018 Remote System Discovery." },
        t1046: { event_type: "discovery_attempt", sev: "medium", host: "BSTOLL-WS-01", source_ip: "91.240.118.20", raw: "Network service discovery. netstat and arp executed. Followed by nltest domain_trusts to map trust relationships across 3 domains. Port 445 open on 12 hosts, 3389 on 8 hosts. This is T1046 Network Service Discovery." },
        t1082: { event_type: "discovery_attempt", sev: "low", host: "ENG-WS-01", source_ip: "10.0.3.10", raw: "System information discovery. systeminfo, whoami all, and ipconfig all executed in sequence. Fingerprinting OS version, installed patches, user privileges, and network configuration. Output piped to text file for exfiltration. This is T1082 System Information Discovery." },
        t1497: { event_type: "discovery_attempt", sev: "medium", host: "BSTOLL-WS-01", source_ip: "10.0.0.12", raw: "Virtualization or sandbox evasion. Malware sample checking for VM artifacts: querying registry for VMware signatures. Sleeping 300s to evade sandbox analysis. Checking for debugger via IsDebuggerPresent API. This is T1497 Virtualization and Sandbox Evasion." },
        // ---- Lateral Movement ----
        t1021_001: { event_type: "lateral_movement_attempt", sev: "critical", host: "CORP-FILE-01", source_ip: "10.0.0.12", raw: "Remote desktop protocol lateral movement. RDP connection from 10.0.0.5 to DC01. EventCode 4624 LogonType 10. Source IP has no prior RDP history to this host. Session lasted 45 minutes. Attacker used stolen admin credentials. This is T1021.001 Remote Desktop Protocol." },
        t1021_002: { event_type: "lateral_movement_attempt", sev: "critical", host: "CORP-SQL-01", source_ip: "192.168.1.45", raw: "SMB Windows Admin Shares lateral movement. PsExec execution detected: services.exe spawned psexesvc.exe on remote host CORP-DC-01. Admin share ADMIN$ accessed from source. PSEXESVC service created and started on target. This is T1021.002 SMB Windows Admin Shares." },
        t1021_006: { event_type: "lateral_movement_attempt", sev: "high", host: "CORP-SQL-01", source_ip: "10.0.0.45", raw: "WinRM lateral movement. wsmprovhost.exe process created on remote host CORP-FILE-01. WinRM session established from BSTOLL-L using stolen credentials. PowerShell remoting used to execute whoami and enumerate shares. This is T1021.006 Windows Remote Management." },
        t1570_001: { event_type: "lateral_movement_attempt", sev: "high", host: "CORP-FILE-01", source_ip: "45.155.205.233", raw: "Remote services using shared credentials. SMB file copy of payload.exe to ADMIN$ share on 3 hosts followed by PsExecCwdService creation. Mass lateral movement to CORP-DC-01, CORP-FILE-01, CORP-SQL-01. All targets executed beacon within 30 seconds. This is T1570.001 Remote Services." },
        t1550_003: { event_type: "lateral_movement_attempt", sev: "high", host: "CORP-DC-02", source_ip: "10.1.1.20", raw: "Pass the ticket. Kerberos ticket reuse detected. TGT from user jdoe presented from host which has no prior Kerberos history. Authentication to CIFS service. Ticket was extracted from memory on compromised host and replayed. This is T1550.003 Pass the Ticket." },
        // ---- Collection ----
        t1005: { event_type: "collection_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "91.240.118.20", raw: "Data from local system. Mass file access detected: 4200 document files accessed in Users Public and shared drives. Accessed by non-owner process powershell.exe. Files indexed and catalogued for selective exfiltration. This is T1005 Data from Local System." },
        t1039: { event_type: "collection_attempt", sev: "medium", host: "CORP-WS-31", source_ip: "192.168.1.45", raw: "Data from shared system. Network share enumeration and bulk copy: robocopy from Finance share to local Temp directory. 12GB of financial documents copied in 8 minutes. This is T1039 Data from Shared System." },
        t1056_001: { event_type: "collection_attempt", sev: "high", host: "CORP-WS-31", source_ip: "10.0.1.42", raw: "Audio capture. Microphone access by unknown process. MediaFoundation API called by powershell.exe. Audio recording to file. 2-hour recording captured. This is T1056.001 Audio Capture." },
        t1113: { event_type: "collection_attempt", sev: "high", host: "CORP-SQL-01", source_ip: "10.0.1.42", raw: "Screen capture. GDI BitBlt API call from non-interactive session. Screenshot saved to Users Public. Consistent with automated desktop capture for data collection. Screenshots taken every 30s for 2 hours. This is T1113 Screen Capture." },
        t1119: { event_type: "collection_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "172.16.1.10", raw: "Automated collection. PowerShell script iterating all mounted drives. Searching for files matching pdf, doc, xls, ppt. Compressing to encrypted 7z archive. 8400 files collected totaling 3.7GB. This is T1119 Automated Collection." },
        // ---- Command and Control ----
        t1071_001: { event_type: "c2_communication", sev: "high", host: "CORP-PROXY-01", source_ip: "10.0.3.55", raw: "Web service C2. DNS tunneling detected. Anomalous TXT query volume to attacker domain. 847 queries in 60s. Beacon pattern consistent with Cobalt Strike DNS beacon. Data exfiltrated via TXT record responses. This is T1071.001 Web Protocols." },
        t1573_002: { event_type: "c2_communication", sev: "high", host: "CORP-PROXY-01", source_ip: "192.168.1.100", raw: "Encrypted C2 channel. TLS connection to attacker server with self-signed certificate. JA3 hash matching known Cobalt Strike profile. Heartbeat every 60s. Traffic appears as legitimate HTTPS but certificate CN mismatch detected. This is T1573.002 Encrypted Channel." },
        t1090: { event_type: "c2_communication", sev: "high", host: "CORP-PROXY-01", source_ip: "192.168.1.45", raw: "Proxy for C2. Tor proxy detected on endpoint. tor.exe process running with SOCKS proxy on localhost. Outbound connections to Tor entry nodes from compromised workstation. C2 traffic routed through Tor to mask origin. This is T1090 Proxy." },
        t1008: { event_type: "c2_communication", sev: "medium", host: "CORP-WS-22", source_ip: "10.0.3.10", raw: "Fallback C2 channels. Primary C2 unreachable. Malware failed over to backup domain. Then to Telegram Bot API as tertiary channel. Redundant infrastructure ensures persistence. This is T1008 Fallback Channels." },
        t1132_001: { event_type: "c2_communication", sev: "medium", host: "CORP-WS-07", source_ip: "172.16.0.20", raw: "Data encoding. Base64-encoded data in HTTP Cookie header to legitimate CDN domain. Data exfiltration via Cloudflare Workers proxy. Traffic appears as normal web browsing. 47MB exfiltrated over 4 hours. This is T1132.001 Data Encoding." },
        // ---- Exfiltration ----
        t1041: { event_type: "exfiltration_attempt", sev: "critical", host: "CORP-DB-02", source_ip: "10.0.0.45", raw: "Exfiltration over C2 channel. 2.3GB uploaded to attacker server over 4 hours via HTTPS. Connection established after data collection script completed. Destination has no prior history. Data includes financial records and customer PII. This is T1041 Exfiltration Over C2 Channel." },
        t1048_002: { event_type: "exfiltration_attempt", sev: "critical", host: "CORP-FILE-01", source_ip: "10.0.1.25", raw: "Exfiltration over alternative protocol. DNS tunneling exfiltration detected. 47MB of encoded data sent via TXT queries to attacker domain. Anomalous DNS query length exceeding 200 chars. Exfil started after business hours. This is T1048.002 Exfiltration Over Alternative Protocol." },
        t1567_002: { event_type: "exfiltration_attempt", sev: "high", host: "CORP-WS-07", source_ip: "91.240.118.20", raw: "Exfiltration to cloud storage. 847 files uploaded to MEGA.nz via API. OAuth token for service account used from anomalous IP. 3.2GB exfiltrated. Cloud storage abuse blends with legitimate backup traffic. This is T1567.002 Exfiltration to Cloud Storage." },
        t1029: { event_type: "exfiltration_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "194.165.12.85", raw: "Scheduled transfer. rsync job to external server configured in cron. Running daily at 02:00. Exfiltrating user Documents. Hidden via log rotation. 47GB exfiltrated over 2 weeks before detection. This is T1029 Scheduled Transfer." },
        // ---- Impact ----
        t1486: { event_type: "impact_attempt", sev: "critical", host: "CORP-SQL-01", source_ip: "185.220.101.45", raw: "Data encrypted for impact. Ransomware detected: vssadmin delete shadows all executed. Then mass file encryption of all drives. .encrypted extension applied to 48000 files. Ransom note dropped in every directory demanding 50 BTC. This is T1486 Data Encrypted for Impact." },
        t1490: { event_type: "impact_attempt", sev: "critical", host: "CORP-DC-01", source_ip: "192.168.1.45", raw: "Inhibit system recovery. bcdedit set recoveryenabled No and bootstatuspolicy ignoreallfailures executed. Preventing system recovery options. VSS shadow copies deleted. Windows Recovery Environment disabled. This is T1490 Inhibit System Recovery." },
        t1485: { event_type: "impact_attempt", sev: "critical", host: "CORP-SQL-01", source_ip: "185.220.101.45", raw: "Data destruction. sdelete.exe used to securely delete 12000 files. Free space wiped with 3 passes. Forensic recovery impossible. Executed after data exfiltration to cause maximum damage. This is T1485 Data Destruction." },
        t1498_001: { event_type: "impact_attempt", sev: "critical", host: "CORP-SQL-01", source_ip: "172.16.0.20", raw: "Network DoS. SYN flood detected. 89000 SYN packets per second to target port 443 from 1200 spoofed source IPs. SYN backlog exhausted. Service unresponsive for 4 hours. This is T1498.001 Direct Network Flood." },
        t1529: { event_type: "impact_attempt", sev: "high", host: "CORP-FILE-01", source_ip: "172.16.1.10", raw: "System shutdown or reboot. shutdown r t 0 f executed by compromised admin account. Forced reboot of domain controller DC01 during business hours. Service disruption to 3400 users. Attack preceded by disabling monitoring services. This is T1529 System Shutdown Reboot." },
        // ---- Reconnaissance ----
        t1595_001: { event_type: "recon_attempt", sev: "medium", host: "CORP-PROXY-01", source_ip: "194.165.12.85", raw: "Active scanning of internet-facing services. masscan scan detected from attacker range. Scanning entire subnet for ports 80, 443, 3389, 22. Scanning 65536 hosts in under 5 minutes. Followed by targeted nmap vulnerability scan. This is T1595.001 Scanning IP Blocks." },
        t1592_004: { event_type: "recon_attempt", sev: "low", host: "CORP-VPN-01", source_ip: "10.0.1.25", raw: "Gather victim host information. Shodan API queries detected from attacker IP. Enumerating open ports and service banners for internal subnet. Correlating results with CVE databases for exploitation planning. This is T1592.004 Client Configurations." },
        t1590_001: { event_type: "recon_attempt", sev: "low", host: "CORP-VPN-01", source_ip: "172.16.1.10", raw: "Gather victim host info via DNS. Reverse DNS sweep of internal subnet using dig. Enumerating internal hostnames for lateral movement planning. 23 hostnames resolved including DC01, FS01, SQL01. This is T1590.001 DNS." },
    };

    function populateScenarios() {
        var sel = $("#rf_scenario");
        if (!sel.length) return;
        sel.empty();
        var tacticOrder = ["Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Credential Access","Discovery","Lateral Movement","Collection","Command and Control","Exfiltration","Impact","Reconnaissance"];
        var tacticMap = {};
        Object.keys(SCENARIOS).forEach(function(key) {
            var tactic = eventToTactic(SCENARIOS[key].event_type);
            if (!tacticMap[tactic]) tacticMap[tactic] = [];
            tacticMap[tactic].push(key);
        });
        tacticOrder.forEach(function(tactic) {
            if (!tacticMap[tactic]) return;
            var og = $("<optgroup>").attr("label", tactic);
            tacticMap[tactic].forEach(function(key) {
                var label = key.toUpperCase().replace("_", ".") + " [" + (SCENARIOS[key].host||"?") + "] " + SCENARIOS[key].raw.substring(0, 55) + "...";
                og.append($("<option>").val(key).text(label));
            });
            sel.append(og);
        });
        var cnt = Object.keys(SCENARIOS).length;
        var hcnt = new Set(Object.values(SCENARIOS).map(function(s){return s.host;})).size;
        $("#rf_scenario_count").text(cnt + " scenarios from " + hcnt + " machines");
        // Select the first real option (skip optgroup labels) and fill all fields
        var firstOpt = sel.find("option").first();
        if (firstOpt.length > 0) {
            var firstKey = firstOpt.val();
            sel.val(firstKey);
            var s = SCENARIOS[firstKey];
            if (s) {
                $("#rf_raw").val(s.raw);
                if (s.sev) $("#rf_severity").val(s.sev);
                if (s.host) $("#rf_host").val(s.host);
                if (s.source_ip) $("#rf_source_ip").val(s.source_ip);
            }
        }
    }

    populateScenarios();

    $(document).on("change", "#rf_scenario", function() {
        var s = SCENARIOS[$(this).val()];
        if (s) {
            $("#rf_raw").val(s.raw);
            if (s.sev) $("#rf_severity").val(s.sev);
            if (s.host) $("#rf_host").val(s.host);
            if (s.source_ip) $("#rf_source_ip").val(s.source_ip);
        }
    });

    $(document).on("click", "#rf_trigger_btn", function(e) {
        e.preventDefault();
        var scenario = $("#rf_scenario").val();
        var s = SCENARIOS[scenario] || SCENARIOS.t1003_001;
        var payload = {
            host: $("#rf_host").val() || s.host || "BSTOLL-L",
            source_ip: s.source_ip || "10.0.0.5",
            event_type: s.event_type,
            raw_event: $("#rf_raw").val() || s.raw,
            severity: s.sev || $("#rf_severity").val() || "high",
            splunk_index: "botsv3",
            additional_context: { scenario: scenario, source_ip: s.source_ip, host: s.host }
        };
        status("Firing signal from " + (s.host||"host") + " to agent...", "#FFBF00");
        $.ajax({
            url: apiBaseUrl + "/trigger",
            type: "POST",
            contentType: "application/json",
            headers: { "X-API-Key": getApiKey() },
            data: JSON.stringify(payload),
            success: function(resp) {
                status("Signal accepted from " + (s.host||"host") + ". task_id=" + resp.task_id + " - poll Predictions tab in ~10s.", "#3ad29f");
                pollTask(resp.task_id);
            },
            error: function(err) {
                status("Trigger failed: " + (err.responseJSON && err.responseJSON.detail || err.statusText) + " - is FastAPI running on :8080?", "#FF0000");
            }
        });
    });

    function pollTask(taskId) {
        var attempts = 0;
        var iv = setInterval(function() {
            $.ajax({
                url: apiBaseUrl + "/trigger/status/" + taskId,
                type: "GET",
                headers: { "X-API-Key": getApiKey() },
                success: function(data) {
                    attempts++;
                    if (data.status === "completed") {
                        clearInterval(iv);
                        var top = data.brief && data.brief.top_prediction;
                        status("Prediction ready. Top: " + (top ? top.technique_id + " (" + Math.round(top.probability*100) + "%)" : "none"), "#3ad29f");
                    } else if (data.status === "failed") {
                        clearInterval(iv);
                        status("Agent failed: " + (data.error || "unknown"), "#FF0000");
                    } else if (attempts > 30) {
                        clearInterval(iv);
                        status("Timed out waiting for agent.", "#FFBF00");
                    } else {
                        status("Agent running... (" + attempts + ")", "#FFBF00");
                    }
                },
                error: function() { attempts++; }
            });
        }, 2000);
    }

    $(document).on("click", "#submitFeedbackBtn", function(e) {
        e.preventDefault();
        var ep = $("#episode_id").val();
        var ttp = $("#technique_id").val();
        var outcome = $("#outcome").val() === "true";
        if (!ep) { alert("Enter an Episode ID"); return; }
        $.ajax({
            url: apiBaseUrl + "/feedback",
            type: "POST",
            contentType: "application/json",
            headers: { "X-API-Key": getApiKey() },
            data: JSON.stringify({ episode_id: ep, confirmed_technique_id: ttp, outcome_confirmed: outcome }),
            success: function(r) {
                status("Feedback saved: " + r.message, "#3ad29f");
                fetchEpisodes();
                fetchHealth();
            },
            error: function(err) {
                status("Feedback error: " + (err.responseJSON && err.responseJSON.detail || err.statusText), "#FF0000");
            }
        });
    });

    function fetchEpisodes() {
        $.ajax({
            url: apiBaseUrl + "/feedback/episodes",
            type: "GET",
            headers: { "X-API-Key": getApiKey() },
            success: function(data) {
                var rows = (data.episodes || []).map(function(ep) {
                    return "<tr><td style='padding:6px'>" + ep.id.substring(0,8) + "...</td><td>" + (ep.host||"-") +
                           "</td><td>" + (ep.signal_type||"-") + "</td><td>" + (ep.confirmed?"yes":"no") +
                           "</td><td>" + (ep.confirmed_technique||"-") + "</td></tr>";
                }).join("");
                $("#rf_episodes_body").html(rows || "<tr><td colspan='5' style='padding:10px;opacity:.6'>No episodes yet</td></tr>");
            },
            error: function() {
                $("#rf_episodes_body").html("<tr><td colspan='5' style='padding:10px;color:#FF0000'>FastAPI not reachable on :8080</td></tr>");
            }
        });
    }
    setTimeout(fetchEpisodes, 1500);
    setInterval(fetchEpisodes, 10000);
});




