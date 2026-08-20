require([
    "jquery",
    "splunkjs/mvc",
    "splunkjs/mvc/simplexml/ready!"
], function($, mvc) {
    console.log("RedForesight feedback_v2.js loaded");

    var apiKeyDefault = "redforesight_demo_key_2026";
    var detectedPort = sessionStorage.getItem("redforesight_api_port") || "8081";

    function getApiKey() {
        var key = sessionStorage.getItem("redforesight_api_key");
        if (!key) {
            key = apiKeyDefault;
            sessionStorage.setItem("redforesight_api_key", key);
        }
        return key || "";
    }

    function getApiPort() {
        var inputPort = $("#rf_api_port").val();
        if (inputPort && inputPort.trim() !== "") {
            var cleanPort = inputPort.trim();
            sessionStorage.setItem("redforesight_api_port", cleanPort);
            return cleanPort;
        }
        return detectedPort || "8081";
    }

    function getApiBaseUrl() {
        var host = window.location.hostname || "127.0.0.1";
        return "http://" + host + ":" + getApiPort() + "/api/v1";
    }

    function getHealthUrl(port) {
        var host = window.location.hostname || "127.0.0.1";
        var p = port || getApiPort();
        return "http://" + host + ":" + p + "/health";
    }

    function status(msg, color) {
        $("#rf_trigger_status,#rf_feedback_status").css("color", color || "#aeb8fe").text(msg);
    }

    function probePorts() {
        var host = window.location.hostname || "127.0.0.1";
        var portsToTry = [getApiPort(), "8081", "8080"];
        
        function tryNext(idx) {
            if (idx >= portsToTry.length) return;
            var testPort = portsToTry[idx];
            $.ajax({
                url: "http://" + host + ":" + testPort + "/health",
                type: "GET",
                timeout: 2000,
                success: function(data) {
                    detectedPort = testPort;
                    sessionStorage.setItem("redforesight_api_port", testPort);
                    if ($("#rf_api_port").length && !$("#rf_api_port").is(":focus")) {
                        $("#rf_api_port").val(testPort);
                    }
                    $("#live_episode_count").text(data.episode_count || 0);
                    console.log("Connected to RedForesight FastAPI on port " + testPort);
                },
                error: function() {
                    tryNext(idx + 1);
                }
            });
        }
        tryNext(0);
    }

    function fetchHealth() {
        $.ajax({
            url: getHealthUrl(),
            type: "GET",
            timeout: 3000,
            success: function(data) {
                $("#live_episode_count").text(data.episode_count || 0);
            },
            error: function() {
                probePorts();
            }
        });
    }
    setTimeout(fetchHealth, 500);
    setInterval(fetchHealth, 5000);

    function eventToTactic(et) {
        var map = {
            "initial_access_attempt":"Initial Access","supply_chain_compromise":"Initial Access","trusted_relationship_abuse":"Initial Access",
            "account_manipulation":"Persistence","execution_attempt":"Execution","persistence_attempt":"Persistence",
            "privilege_escalation_attempt":"Privilege Escalation","defense_evasion_attempt":"Defense Evasion",
            "credential_access_attempt":"Credential Access","discovery_attempt":"Discovery","lateral_movement_attempt":"Lateral Movement",
            "collection_attempt":"Collection","c2_communication":"Command and Control","exfiltration_attempt":"Exfiltration",
            "impact_attempt":"Impact","recon_attempt":"Reconnaissance"
        };
        return map[et] || "Other";
    }

    var SCENARIOS = {
        // ---- Initial Access ----
        phishing_macro: { event_type: "initial_access_attempt", sev: "high", host: "CORP-WS-07", source_ip: "192.168.1.45", raw: "User opened a malicious Word document. The document ran a macro that launched PowerShell." },
        phishing_link: { event_type: "initial_access_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "172.16.0.5", raw: "User clicked a link in a phishing email. The link opened a fake login page that stole their password." },
        phishing_pdf: { event_type: "initial_access_attempt", sev: "medium", host: "WIN-DESKTOP-05", source_ip: "10.0.0.12", raw: "User opened a PDF from an unknown sender. The PDF had a hidden exploit." },
        log4shell: { event_type: "initial_access_attempt", sev: "critical", host: "CORP-WS-07", source_ip: "172.16.0.5", raw: "Attacker sent a Log4Shell exploit to the web server. The server ran the attacker code." },
        sql_injection: { event_type: "initial_access_attempt", sev: "critical", host: "CORP-WEB-01", source_ip: "185.220.101.45", raw: "SQL injection on the login page. Attacker tried to bypass authentication." },
        stolen_password: { event_type: "initial_access_attempt", sev: "high", host: "WIN-DESKTOP-05", source_ip: "192.168.1.100", raw: "Someone logged in with a stolen password from a country the user never visited." },
        vpn_brute: { event_type: "initial_access_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "10.0.1.42", raw: "Attacker tried 500 passwords on VPN login and found the right one for a service account." },
        usb_drop: { event_type: "initial_access_attempt", sev: "high", host: "CORP-WS-12", source_ip: "192.168.1.100", raw: "User found a USB drive in the parking lot and plugged it in. It ran malware automatically." },
        fake_update: { event_type: "initial_access_attempt", sev: "high", host: "CORP-WEB-01", source_ip: "192.168.1.100", raw: "A fake browser update popup tricked a user into downloading and running malware." },
        supply_chain: { event_type: "initial_access_attempt", sev: "critical", host: "CORP-WS-12", source_ip: "10.0.1.42", raw: "A trusted software vendor was hacked. Their update installed malware on our systems." },
        // ---- Execution ----
        powershell_download: { event_type: "execution_attempt", sev: "high", host: "CORP-WS-07", source_ip: "172.16.0.5", raw: "PowerShell downloaded a file from the internet. The file was malware." },
        cmd_adduser: { event_type: "execution_attempt", sev: "high", host: "CORP-WS-07", source_ip: "91.240.118.20", raw: "Command prompt created a new user account called backdoor and made it an admin." },
        wscript_run: { event_type: "execution_attempt", sev: "medium", host: "WIN-DESKTOP-05", source_ip: "10.0.0.12", raw: "A VBScript file ran on the computer. The script downloaded and ran a second file." },
        python_payload: { event_type: "execution_attempt", sev: "high", host: "CORP-WS-07", source_ip: "192.168.1.100", raw: "Python ran code that injected malware into another program." },
        rundll32_loaddll: { event_type: "execution_attempt", sev: "medium", host: "WIN-DESKTOP-05", source_ip: "10.0.0.12", raw: "rundll32.exe loaded a suspicious DLL from the temp folder. The DLL was malware." },
        scheduled_task_run: { event_type: "execution_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "10.0.0.12", raw: "A scheduled task ran update.exe from the temp folder at 3 AM." },
        service_install: { event_type: "execution_attempt", sev: "high", host: "CORP-WS-22", source_ip: "10.0.1.42", raw: "A new Windows service was installed. The service runs a file from the Users folder." },
        mshta_html: { event_type: "execution_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "192.168.1.45", raw: "mshta.exe ran a remote HTML file with malicious JavaScript." },
        certutil_decode: { event_type: "execution_attempt", sev: "medium", host: "WIN-DESKTOP-05", source_ip: "91.240.118.20", raw: "certutil.exe decoded a hidden file. The decoded file was malware." },
        winrm_exec: { event_type: "execution_attempt", sev: "high", host: "WIN-DESKTOP-05", source_ip: "192.168.1.45", raw: "WinRM was used to run commands on another computer remotely." },
        // ---- Persistence ----
        registry_run_key: { event_type: "persistence_attempt", sev: "high", host: "CORP-WS-07", source_ip: "10.0.0.5", raw: "Malware added itself to the Windows startup registry key so it runs on every boot." },
        new_local_user: { event_type: "persistence_attempt", sev: "high", host: "CORP-FILE-01", source_ip: "192.168.1.100", raw: "A new user account was created at night. The account was added to the admin group." },
        startup_folder: { event_type: "persistence_attempt", sev: "medium", host: "CORP-DC-02", source_ip: "45.155.205.233", raw: "A shortcut was placed in the Windows Startup folder. It runs malware on every login." },
        wmi_subscription: { event_type: "persistence_attempt", sev: "high", host: "CORP-WS-12", source_ip: "91.240.118.20", raw: "A hidden WMI event runs a command every 5 minutes. This is hard to detect." },
        dll_hijack: { event_type: "persistence_attempt", sev: "medium", host: "CORP-DC-02", source_ip: "91.240.118.20", raw: "Malware replaced a legitimate DLL. It runs every time the real program opens." },
        create_service: { event_type: "persistence_attempt", sev: "high", host: "CORP-FILE-01", source_ip: "10.0.0.5", raw: "A fake Windows service called WindowsHelper was created. It runs malware as SYSTEM." },
        ssh_key: { event_type: "persistence_attempt", sev: "high", host: "CORP-WS-07", source_ip: "194.165.12.85", raw: "An SSH key was added to a Linux server. The attacker can log in without a password anytime." },
        office_macro_persist: { event_type: "persistence_attempt", sev: "medium", host: "CORP-DC-02", source_ip: "172.16.0.5", raw: "An Office template was modified to run malware every time Word opens." },
        app_dll_inject: { event_type: "persistence_attempt", sev: "medium", host: "CORP-DC-02", source_ip: "194.165.12.85", raw: "Malware injected itself into a running app so it survives even if the original file is deleted." },
        browser_extension: { event_type: "persistence_attempt", sev: "low", host: "CORP-DC-02", source_ip: "45.155.205.233", raw: "A malicious browser extension was installed. It can read all web pages and steal passwords." },
        // ---- Privilege Escalation ----
        uac_bypass: { event_type: "privilege_escalation_attempt", sev: "high", host: "CORP-WS-22", source_ip: "192.168.1.100", raw: "Attacker used a UAC bypass trick to get admin rights without a password prompt." },
        exploit_pe: { event_type: "privilege_escalation_attempt", sev: "critical", host: "CORP-DC-01", source_ip: "194.165.12.85", raw: "A known vulnerability was exploited to get SYSTEM level access." },
        token_steal: { event_type: "privilege_escalation_attempt", sev: "high", host: "CORP-WS-07", source_ip: "10.0.0.12", raw: "Attacker stole a SYSTEM token from a running process and used it to run commands as admin." },
        add_to_admins: { event_type: "privilege_escalation_attempt", sev: "high", host: "CORP-WS-22", source_ip: "194.165.12.85", raw: "A normal user was added to the Administrators group using stolen credentials." },
        dll_sideload: { event_type: "privilege_escalation_attempt", sev: "medium", host: "CORP-SQL-01", source_ip: "10.0.1.42", raw: "A signed Microsoft program was tricked into loading a malicious DLL that runs as admin." },
        unquoted_service: { event_type: "privilege_escalation_attempt", sev: "medium", host: "CORP-SQL-01", source_ip: "192.168.1.100", raw: "An unquoted service path was exploited to run malware as SYSTEM." },
        weak_permissions: { event_type: "privilege_escalation_attempt", sev: "medium", host: "CORP-WS-22", source_ip: "10.0.0.12", raw: "A service had weak file permissions. Attacker replaced the service file with malware." },
        sudo_misuse: { event_type: "privilege_escalation_attempt", sev: "high", host: "CORP-WS-22", source_ip: "172.16.0.5", raw: "A sudo configuration mistake let a normal user run commands as root on Linux." },
        // ---- Defense Evasion ----
        disable_defender: { event_type: "defense_evasion_attempt", sev: "critical", host: "CORP-WS-07", source_ip: "192.168.1.100", raw: "Windows Defender was turned off. This let the attacker install malware without detection." },
        clear_logs: { event_type: "defense_evasion_attempt", sev: "high", host: "BSTOLL-L", source_ip: "10.0.2.18", raw: "The Security event log was cleared to remove evidence of the attack." },
        masquerade_name: { event_type: "defense_evasion_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "10.0.0.12", raw: "Malware renamed itself to look like a real Windows program but ran from the wrong folder." },
        obfuscation: { event_type: "defense_evasion_attempt", sev: "medium", host: "CORP-WS-31", source_ip: "10.0.0.5", raw: "A PowerShell script was heavily encoded to hide what it does from antivirus." },
        delete_evidence: { event_type: "defense_evasion_attempt", sev: "high", host: "CORP-WS-31", source_ip: "10.0.2.18", raw: "Attacker deleted malware files after they were used to clean up traces." },
        disable_firewall: { event_type: "defense_evasion_attempt", sev: "high", host: "CORP-DC-01", source_ip: "185.220.101.45", raw: "The Windows Firewall was turned off so the attacker could connect without being blocked." },
        sign_malware: { event_type: "defense_evasion_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "10.0.0.5", raw: "Malware was signed with a stolen certificate so it looks like trusted software." },
        process_hollowing: { event_type: "defense_evasion_attempt", sev: "high", host: "CORP-WS-31", source_ip: "45.155.205.233", raw: "Malware injected its code into a legitimate running process to hide from detection." },
        // ---- Credential Access ----
        lsass_dump: { event_type: "credential_access_attempt", sev: "critical", host: "CORP-DC-02", source_ip: "185.220.101.45", raw: "Malware read the memory of lsass.exe to steal all passwords stored on the computer." },
        sam_dump: { event_type: "credential_access_attempt", sev: "critical", host: "CORP-SQL-01", source_ip: "10.0.1.42", raw: "Attacker copied the SAM registry hive to crack all Windows passwords offline." },
        dcsync: { event_type: "credential_access_attempt", sev: "critical", host: "CORP-DC-02", source_ip: "185.220.101.45", raw: "Attacker used DCSync to copy all domain passwords from the domain controller." },
        kerberoast: { event_type: "credential_access_attempt", sev: "high", host: "CORP-SQL-01", source_ip: "172.16.0.5", raw: "Attacker requested Kerberos tickets to crack a service account password offline." },
        password_spray: { event_type: "credential_access_attempt", sev: "high", host: "CORP-SQL-01", source_ip: "10.0.0.5", raw: "Attacker tried one password against 100 different user accounts at the same time." },
        brute_force: { event_type: "credential_access_attempt", sev: "high", host: "CORP-DC-01", source_ip: "10.0.1.42", raw: "Attacker tried 1000 passwords on one account until they found the right one." },
        keylogger: { event_type: "credential_access_attempt", sev: "high", host: "CORP-SQL-01", source_ip: "10.0.2.18", raw: "A keylogger was found recording everything the user types including passwords." },
        credential_browser: { event_type: "credential_access_attempt", sev: "medium", host: "CORP-DC-01", source_ip: "192.168.1.45", raw: "Malware stole saved passwords from the user web browser Chrome and Edge." },
        ntlm_relay: { event_type: "credential_access_attempt", sev: "high", host: "BSTOLL-L", source_ip: "194.165.12.85", raw: "Attacker captured and relayed NTLM authentication to access another system." },
        credential_file: { event_type: "credential_access_attempt", sev: "medium", host: "BSTOLL-L", source_ip: "172.16.0.5", raw: "Malware searched the hard drive for files containing passwords." },
        // ---- Discovery ----
        scan_network: { event_type: "discovery_attempt", sev: "low", host: "BSTOLL-L", source_ip: "10.0.0.5", raw: "Attacker ran nmap to scan the network and find other computers to attack." },
        enum_users: { event_type: "discovery_attempt", sev: "low", host: "CORP-WS-07", source_ip: "91.240.118.20", raw: "Attacker ran net user to list all user accounts in the domain." },
        enum_shares: { event_type: "discovery_attempt", sev: "low", host: "CORP-WS-07", source_ip: "185.220.101.45", raw: "Attacker searched for shared folders on the network to find files to steal." },
        system_info: { event_type: "discovery_attempt", sev: "low", host: "CORP-WS-22", source_ip: "10.0.0.12", raw: "Attacker ran systeminfo to learn about the computer OS version and patches." },
        find_admins: { event_type: "discovery_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "172.16.0.5", raw: "Attacker searched for all admin accounts to know who has the most access." },
        port_scan: { event_type: "discovery_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "185.220.101.45", raw: "A port scan was run to find open ports on the servers." },
        query_registry: { event_type: "discovery_attempt", sev: "low", host: "BSTOLL-L", source_ip: "10.0.0.12", raw: "Attacker searched the Windows registry for installed software and settings." },
        check_vm: { event_type: "discovery_attempt", sev: "low", host: "ENG-WS-01", source_ip: "194.165.12.85", raw: "Malware checked if it was running inside a virtual machine to avoid being analyzed." },
        // ---- Lateral Movement ----
        rdp_connect: { event_type: "lateral_movement_attempt", sev: "high", host: "CORP-WS-22", source_ip: "10.0.0.5", raw: "Attacker used Remote Desktop to connect to another computer using stolen credentials." },
        psexec_run: { event_type: "lateral_movement_attempt", sev: "high", host: "CORP-SQL-01", source_ip: "192.168.1.45", raw: "Attacker used PsExec to run commands on another computer remotely." },
        winrm_remote: { event_type: "lateral_movement_attempt", sev: "high", host: "CORP-WS-22", source_ip: "10.0.0.5", raw: "Attacker used WinRM to run PowerShell on another computer in the network." },
        smb_copy: { event_type: "lateral_movement_attempt", sev: "medium", host: "CORP-DC-02", source_ip: "192.168.1.100", raw: "Attacker copied malware to a shared folder on another computer." },
        pass_the_hash: { event_type: "lateral_movement_attempt", sev: "critical", host: "CORP-WS-22", source_ip: "192.168.1.100", raw: "Attacker used a stolen password hash to log in without knowing the actual password." },
        pass_the_ticket: { event_type: "lateral_movement_attempt", sev: "critical", host: "CORP-DC-01", source_ip: "194.165.12.85", raw: "Attacker used a stolen Kerberos ticket to access systems without a password." },
        ssh_lateral: { event_type: "lateral_movement_attempt", sev: "high", host: "CORP-FILE-01", source_ip: "172.16.0.5", raw: "Attacker used SSH to jump from one Linux server to another." },
        wmi_remote: { event_type: "lateral_movement_attempt", sev: "medium", host: "CORP-DC-01", source_ip: "194.165.12.85", raw: "Attacker used WMI to run commands on another Windows computer." },
        // ---- Collection ----
        copy_files: { event_type: "collection_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "192.168.1.100", raw: "Attacker copied 5000 documents from a shared folder to prepare for exfiltration." },
        screenshot: { event_type: "collection_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "10.0.0.12", raw: "Malware took screenshots of the user desktop every 30 seconds." },
        audio_record: { event_type: "collection_attempt", sev: "medium", host: "CORP-FILE-01", source_ip: "185.220.101.45", raw: "Malware turned on the microphone to record conversations in the room." },
        database_dump: { event_type: "collection_attempt", sev: "high", host: "CORP-WS-31", source_ip: "185.220.101.45", raw: "Attacker dumped the entire customer database to a file." },
        email_scrape: { event_type: "collection_attempt", sev: "medium", host: "CORP-SQL-01", source_ip: "10.0.1.42", raw: "Malware searched the user emails for attachments with sensitive data." },
        compress_data: { event_type: "collection_attempt", sev: "low", host: "CORP-SQL-01", source_ip: "172.16.0.5", raw: "Attacker compressed 10GB of stolen files into a password-protected ZIP." },
        // ---- Command and Control ----
        dns_tunneling: { event_type: "c2_communication", sev: "high", host: "CORP-WS-22", source_ip: "10.0.1.42", raw: "Attacker used DNS queries to secretly send data out of the network." },
        https_c2: { event_type: "c2_communication", sev: "high", host: "CORP-WS-44", source_ip: "192.168.1.100", raw: "Malware connected to attacker server over HTTPS. It looked like normal web browsing." },
        tor_proxy: { event_type: "c2_communication", sev: "medium", host: "CORP-WS-44", source_ip: "10.0.0.12", raw: "Attacker used Tor to hide their location. Traffic was routed through 3 countries." },
        icmp_ping: { event_type: "c2_communication", sev: "medium", host: "CORP-WS-07", source_ip: "91.240.118.20", raw: "Attacker used ping packets to send hidden commands. This is hard to detect." },
        webhook_c2: { event_type: "c2_communication", sev: "medium", host: "CORP-PROXY-01", source_ip: "172.16.0.5", raw: "Malware used a Discord webhook to receive commands from the attacker." },
        fallback_c2: { event_type: "c2_communication", sev: "low", host: "BSTOLL-L", source_ip: "10.0.1.42", raw: "When the main C2 server was blocked malware switched to a backup server." },
        // ---- Exfiltration ----
        upload_c2: { event_type: "exfiltration_attempt", sev: "critical", host: "CORP-DB-02", source_ip: "194.165.12.85", raw: "Attacker uploaded 5GB of stolen files to their server over HTTPS." },
        dns_exfil: { event_type: "exfiltration_attempt", sev: "critical", host: "CORP-FILE-01", source_ip: "192.168.1.100", raw: "Attacker sent stolen data hidden inside DNS queries to bypass the firewall." },
        cloud_upload: { event_type: "exfiltration_attempt", sev: "high", host: "CORP-DB-02", source_ip: "194.165.12.85", raw: "Attacker uploaded stolen files to a personal cloud storage account." },
        ftp_exfil: { event_type: "exfiltration_attempt", sev: "high", host: "CORP-DB-02", source_ip: "192.168.1.45", raw: "Attacker used FTP to transfer stolen files to an external server." },
        email_exfil: { event_type: "exfiltration_attempt", sev: "medium", host: "CORP-DB-02", source_ip: "10.0.0.5", raw: "Attacker emailed stolen documents to a personal Gmail account." },
        scheduled_exfil: { event_type: "exfiltration_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "185.220.101.45", raw: "Malware was set to send stolen data at 2 AM every night to avoid detection." },
        // ---- Impact ----
        ransomware: { event_type: "impact_attempt", sev: "critical", host: "CORP-SQL-01", source_ip: "185.220.101.45", raw: "Ransomware encrypted all files on the server. Attacker demanded 50 Bitcoin to unlock them." },
        delete_shadows: { event_type: "impact_attempt", sev: "critical", host: "CORP-DC-02", source_ip: "185.220.101.45", raw: "Attacker deleted all Windows backup copies so the ransomware cannot be reversed." },
        data_wipe: { event_type: "impact_attempt", sev: "critical", host: "CORP-FILE-01", source_ip: "192.168.1.100", raw: "Attacker permanently deleted all files on the database server. Data cannot be recovered." },
        ddos_syn: { event_type: "impact_attempt", sev: "high", host: "CORP-DC-02", source_ip: "10.0.0.12", raw: "A DDoS attack sent 100000 requests per second to the website. The website went offline." },
        force_shutdown: { event_type: "impact_attempt", sev: "high", host: "CORP-DC-02", source_ip: "192.168.1.100", raw: "Attacker forced the domain controller to shut down. 3000 users lost access." },
        encrypt_db: { event_type: "impact_attempt", sev: "critical", host: "CORP-FILE-01", source_ip: "91.240.118.20", raw: "Attacker encrypted the SQL database. No one could access customer records." },
        disk_wipe: { event_type: "impact_attempt", sev: "critical", host: "CORP-SQL-01", source_ip: "10.0.0.12", raw: "Attacker wiped the entire hard drive. The operating system was destroyed." },
        deface_website: { event_type: "impact_attempt", sev: "medium", host: "CORP-SQL-01", source_ip: "185.220.101.45", raw: "Attacker replaced the company website homepage with a defacement message." },
        stop_services: { event_type: "impact_attempt", sev: "high", host: "CORP-FILE-01", source_ip: "10.0.2.18", raw: "Attacker stopped all critical Windows services causing a system-wide outage." },
        corrupt_files: { event_type: "impact_attempt", sev: "high", host: "CORP-SQL-01", source_ip: "192.168.1.45", raw: "Attacker corrupted all Excel files on the file server by overwriting them with random data." },
        // ---- Reconnaissance ----
        port_scan_external: { event_type: "recon_attempt", sev: "low", host: "CORP-WS-07", source_ip: "10.0.0.5", raw: "Someone scanned all our public IP addresses looking for open ports." },
        subdomain_enum: { event_type: "recon_attempt", sev: "low", host: "CORP-PROXY-01", source_ip: "10.0.2.18", raw: "Attacker searched for hidden subdomains on our website using DNS queries." },
        google_dork: { event_type: "recon_attempt", sev: "low", host: "CORP-WEB-01", source_ip: "10.0.0.5", raw: "Attacker used Google to find sensitive files exposed on our website." },
        whois_lookup: { event_type: "recon_attempt", sev: "low", host: "CORP-WEB-01", source_ip: "192.168.1.45", raw: "Attacker looked up our domain registration info to find email addresses and servers." },
        shodan_scan: { event_type: "recon_attempt", sev: "low", host: "CORP-WEB-01", source_ip: "10.0.0.12", raw: "Attacker used Shodan to find all our internet-facing devices and their open ports." },
        email_harvest: { event_type: "recon_attempt", sev: "low", host: "CORP-VPN-01", source_ip: "10.0.0.12", raw: "Attacker collected employee email addresses from our website for a phishing campaign." },
        tech_stack_scan: { event_type: "recon_attempt", sev: "low", host: "CORP-VPN-01", source_ip: "185.220.101.45", raw: "Attacker identified what software and versions our website uses to find vulnerabilities." },
        dns_zone: { event_type: "recon_attempt", sev: "medium", host: "CORP-WEB-01", source_ip: "185.220.101.45", raw: "Attacker tried to download our entire DNS zone file to map our network." },
        social_engineering: { event_type: "recon_attempt", sev: "low", host: "CORP-WEB-01", source_ip: "45.155.205.233", raw: "Attacker created fake LinkedIn profiles to learn about our IT staff and systems." },
        wifi_scan: { event_type: "recon_attempt", sev: "low", host: "CORP-WS-07", source_ip: "172.16.0.5", raw: "Someone scanned our office WiFi from outside the building looking for weak passwords." },
        // ---- OWASP Top 10 ----
        owasp_a01_bac: { event_type: "initial_access_attempt", sev: "critical", host: "CORP-WEB-01", source_ip: "10.0.1.42", raw: "OWASP A01 - Broken Access Control. Attacker accessed admin panel by changing URL from /user to /admin without authentication." },
        owasp_a02_crypto: { event_type: "initial_access_attempt", sev: "high", host: "CORP-WS-22", source_ip: "10.0.1.42", raw: "OWASP A02 - Cryptographic Failures. Passwords stored in plain text in database. Attacker stole the database and read all passwords directly." },
        owasp_a03_injection: { event_type: "initial_access_attempt", sev: "critical", host: "CORP-WS-12", source_ip: "10.0.0.5", raw: "OWASP A03 - Injection. SQL injection in login form let attacker bypass authentication and access all user data." },
        owasp_a04_xxd: { event_type: "initial_access_attempt", sev: "high", host: "CORP-APP-01", source_ip: "91.240.118.20", raw: "OWASP A04 - Insecure Design. Application has no rate limiting. Attacker sent 10000 login attempts without being blocked." },
        owasp_a05_misconfig: { event_type: "initial_access_attempt", sev: "high", host: "CORP-WEB-01", source_ip: "185.220.101.45", raw: "OWASP A05 - Security Misconfiguration. Default admin password was never changed. Attacker logged in with admin/admin." },
        owasp_a06_vuln: { event_type: "initial_access_attempt", sev: "critical", host: "CORP-APP-01", source_ip: "91.240.118.20", raw: "OWASP A06 - Vulnerable Components. Old version of Log4j library was exploited. Attacker sent a crafted string that ran code on the server." },
        owasp_a07_auth: { event_type: "initial_access_attempt", sev: "high", host: "CORP-WS-22", source_ip: "45.155.205.233", raw: "OWASP A07 - Identification and Authentication Failures. Attacker used stolen session cookies to impersonate a logged-in user without a password." },
        owasp_a08_data: { event_type: "exfiltration_attempt", sev: "critical", host: "CORP-WS-07", source_ip: "10.0.0.5", raw: "OWASP A08 - Software and Data Integrity Failures. A trusted plugin was replaced with a malicious version that stole user data." },
        owasp_a09_logging: { event_type: "defense_evasion_attempt", sev: "medium", host: "CORP-APP-01", source_ip: "10.0.0.5", raw: "OWASP A09 - Security Logging and Monitoring Failures. Attacker deleted all logs. No one noticed the breach for 3 weeks." },
        owasp_a10_ssrf: { event_type: "initial_access_attempt", sev: "critical", host: "CORP-WEB-01", source_ip: "91.240.118.20", raw: "OWASP A10 - Server-Side Request Forgery. Attacker tricked the server into fetching data from internal network behind the firewall." },
        // ---- Threat Models - STRIDE ----
        tm_stride_spoofing: { event_type: "initial_access_attempt", sev: "high", host: "CORP-APP-01", source_ip: "45.155.205.233", raw: "STRIDE Spoofing. Attacker impersonated a legitimate user by stealing their session token and accessing the system as them." },
        tm_stride_tampering: { event_type: "defense_evasion_attempt", sev: "high", host: "CORP-FILE-01", source_ip: "185.220.101.45", raw: "STRIDE Tampering. Attacker modified a database record to change their account balance without authorization." },
        tm_stride_repudiation: { event_type: "defense_evasion_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "185.220.101.45", raw: "STRIDE Repudiation. Attacker deleted all audit logs so they can deny performing the malicious action. No evidence left behind." },
        tm_stride_info_disclosure: { event_type: "exfiltration_attempt", sev: "critical", host: "CORP-APP-01", source_ip: "192.168.1.45", raw: "STRIDE Information Disclosure. Attacker accessed a hidden API endpoint and downloaded all customer data including passwords and credit cards." },
        tm_stride_dos: { event_type: "impact_attempt", sev: "critical", host: "CORP-APP-01", source_ip: "10.0.1.42", raw: "STRIDE Denial of Service. Attacker flooded the web server with 50000 requests per second. The server crashed and was offline for 4 hours." },
        tm_stride_eop: { event_type: "privilege_escalation_attempt", sev: "critical", host: "CORP-WS-22", source_ip: "45.155.205.233", raw: "STRIDE Elevation of Privilege. A normal user exploited a bug to gain admin rights and access all system controls." },
        // ---- Threat Models - DREAD ----
        tm_dread_damage: { event_type: "impact_attempt", sev: "critical", host: "CORP-WEB-01", source_ip: "45.155.205.233", raw: "DREAD Damage Potential 10. Attack could destroy all data on the server and cause total business shutdown." },
        tm_dread_reproducibility: { event_type: "initial_access_attempt", sev: "high", host: "CORP-WS-07", source_ip: "185.220.101.45", raw: "DREAD Reproducibility 9. The SQL injection attack can be reproduced by anyone with a web browser. No special tools needed." },
        tm_dread_exploitability: { event_type: "initial_access_attempt", sev: "high", host: "CORP-WEB-01", source_ip: "10.0.1.42", raw: "DREAD Exploitability 8. The vulnerability is easy to exploit. A script kiddie could do it with a YouTube tutorial." },
        tm_dread_affected_users: { event_type: "exfiltration_attempt", sev: "critical", host: "CORP-WS-07", source_ip: "192.168.1.45", raw: "DREAD Affected Users 10. All 50000 customers would be affected. Their personal data would be exposed." },
        tm_dread_discoverability: { event_type: "recon_attempt", sev: "medium", host: "CORP-WS-22", source_ip: "185.220.101.45", raw: "DREAD Discoverability 7. The vulnerability is hidden in a rarely used feature but can be found with automated scanners." },
        // ---- Threat Models - Cyber Kill Chain ----
        tm_killchain_recon: { event_type: "recon_attempt", sev: "low", host: "BSTOLL-L", source_ip: "10.0.1.42", raw: "Cyber Kill Chain Step 1 Reconnaissance. Attacker gathered information about the company by scanning LinkedIn and public websites." },
        tm_killchain_weaponize: { event_type: "initial_access_attempt", sev: "high", host: "CORP-FILE-01", source_ip: "45.155.205.233", raw: "Cyber Kill Chain Step 2 Weaponization. Attacker built a custom malware payload and packaged it inside a fake PDF invoice." },
        tm_killchain_deliver: { event_type: "initial_access_attempt", sev: "high", host: "CORP-DC-01", source_ip: "192.168.1.45", raw: "Cyber Kill Chain Step 3 Delivery. Attacker sent the weaponized PDF as an email attachment to 50 employees." },
        tm_killchain_exploit: { event_type: "initial_access_attempt", sev: "critical", host: "CORP-WS-22", source_ip: "91.240.118.20", raw: "Cyber Kill Chain Step 4 Exploitation. One employee opened the PDF. The exploit ran automatically and installed malware on their computer." },
        tm_killchain_install: { event_type: "persistence_attempt", sev: "high", host: "CORP-FILE-01", source_ip: "185.220.101.45", raw: "Cyber Kill Chain Step 5 Installation. The malware installed a backdoor that survives reboots and connects to attacker server every hour." },
        tm_killchain_c2: { event_type: "c2_communication", sev: "high", host: "CORP-WS-07", source_ip: "91.240.118.20", raw: "Cyber Kill Chain Step 6 Command and Control. The backdoor connected to attacker server and is now receiving commands remotely." },
        tm_killchain_action: { event_type: "impact_attempt", sev: "critical", host: "CORP-APP-01", source_ip: "45.155.205.233", raw: "Cyber Kill Chain Step 7 Actions on Objectives. Attacker is now stealing data and encrypting files for ransom. The full attack chain is complete." },
        // ---- Threat Models - Attack Trees ----
        tm_attacktree_data: { event_type: "exfiltration_attempt", sev: "critical", host: "CORP-WS-22", source_ip: "45.155.205.233", raw: "Attack Tree - Steal Data. Goal: Steal customer database. Path: Phishing email then PowerShell then database dump then exfiltration via DNS." },
        tm_attacktree_ransom: { event_type: "impact_attempt", sev: "critical", host: "CORP-SQL-01", source_ip: "91.240.118.20", raw: "Attack Tree - Deploy Ransomware. Goal: Encrypt all files for ransom. Path: Exploit vulnerability then escalate privileges then disable antivirus then run ransomware." },
    };

    function populateScenarios() {
        var sel = $("#rf_scenario");
        if (!sel.length) return;
        sel.empty();
        var tacticOrder = ["Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Credential Access","Discovery","Lateral Movement","Collection","Command and Control","Exfiltration","Impact","Reconnaissance","OWASP Top 10","Threat Models - STRIDE","Threat Models - DREAD","Threat Models - Cyber Kill Chain","Threat Models - Attack Trees"];
        var tacticMap = {};
        Object.keys(SCENARIOS).forEach(function(key) {
            var tactic = '';
            if (key.indexOf('owasp_') === 0) {
                tactic = 'OWASP Top 10';
            } else if (key.indexOf('tm_stride') === 0) {
                tactic = 'Threat Models - STRIDE';
            } else if (key.indexOf('tm_dread') === 0) {
                tactic = 'Threat Models - DREAD';
            } else if (key.indexOf('tm_killchain') === 0) {
                tactic = 'Threat Models - Cyber Kill Chain';
            } else if (key.indexOf('tm_attacktree') === 0) {
                tactic = 'Threat Models - Attack Trees';
            } else {
                tactic = eventToTactic(SCENARIOS[key].event_type);
            }
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

    // Helper functions for terminal logging
    function appendTerminalLine(msg, type) {
        var term = $("#rf_terminal");
        if (!term.length) return;
        var timeStr = new Date().toLocaleTimeString();
        var cls = type || "info";
        var lineHtml = "<div class=\"line " + cls + "\">[" + timeStr + "] " + msg + "</div>";
        term.append(lineHtml);
        term.scrollTop(term[0].scrollHeight);

        // Also push to POV terminal if open on page
        var povTerm = $("#rf_pov_terminal");
        if (povTerm.length) {
            povTerm.find(".rf-blink").remove();
            povTerm.append("<div class=\"rf-terminal-line rf-" + cls + "\">[" + timeStr + "] " + msg + "</div>");
            povTerm.append("<div class=\"rf-terminal-line rf-prompt rf-blink\">_</div>");
            povTerm.scrollTop(povTerm[0].scrollHeight);
        }
    }

    function updatePipelineSteps(currentStep, isFailed) {
        $("#rf_pipeline").show();
        var stepIds = ["pipe_ingest", "pipe_splunk", "pipe_classify", "pipe_gametree", "pipe_llm", "pipe_brief"];
        
        stepIds.forEach(function(id, idx) {
            var stepNum = idx + 1;
            var el = $("#" + id);
            if (!el.length) return;
            
            el.removeClass("active done failed");
            if (stepNum < currentStep) {
                el.addClass("done");
            } else if (stepNum === currentStep) {
                if (isFailed) {
                    el.addClass("failed").css("border-color", "#FF0000").css("color", "#FF0000");
                } else {
                    el.addClass("active");
                }
            }
        });
    }

    function renderPredictions(brief) {
        var container = $("#rf_predictions");
        if (!container.length) return;
        container.empty();

        if (!brief || !brief.ranked_predictions || brief.ranked_predictions.length === 0) {
            container.html("<div class=\"rf-pred\" style=\"color:#FFBF00\">No predictions generated.</div>");
            return;
        }

        var html = "<div style=\"margin-bottom:10px;font-weight:bold;color:#3ad29f;font-size:15px\">Ranked Next Attacker Move Predictions</div>";
        
        brief.ranked_predictions.forEach(function(move, idx) {
            var rank = idx + 1;
            var probPct = Math.round((move.probability || 0) * 100);
            var probColor = probPct >= 60 ? "#e94560" : probPct >= 30 ? "#f5a623" : "#3ad29f";
            var confClass = move.confidence_tier === "high" ? "rf-badge-red" : move.confidence_tier === "medium" ? "rf-badge-yellow" : "rf-badge-green";
            
            html += "<div class=\"rf-pred\">";
            html += "  <div style=\"display:flex;align-items:center;justify-content:space-between\">";
            html += "    <div>";
            html += "      <span class=\"rf-pred-rank\">" + rank + "</span>";
            html += "      <span class=\"rf-pred-name\">" + (move.technique_id || "") + " — " + (move.technique_name || "Unknown") + "</span>";
            html += "      <div class=\"rf-pred-tactic\">Tactic: <b>" + (move.tactic || "Unknown") + "</b></div>";
            html += "    </div>";
            html += "    <div style=\"text-align:right\">";
            html += "      <span class=\"rf-pred-pct\" style=\"color:" + probColor + "\">" + probPct + "%</span>";
            html += "      <div class=\"rf-pred-conf\" style=\"color:" + probColor + "\">Confidence: " + (move.confidence_tier || "low").toUpperCase() + "</div>";
            html += "    </div>";
            html += "  </div>";

            html += "  <div class=\"rf-pred-bar\"><div class=\"rf-pred-fill\" style=\"width:" + probPct + "%;background:" + probColor + "\"></div></div>";
            
            if (move.reasoning) {
                html += "  <div class=\"rf-pred-reason\">\"" + move.reasoning + "\"</div>";
            }
            if (move.defender_action) {
                html += "  <div style=\"margin-top:8px;background:#16213e;padding:8px;border-left:3px solid #3ad29f;font-size:12px;color:#fff\">";
                html += "    <b>Recommended Action:</b> " + move.defender_action;
                html += "  </div>";
            }
            // SPL removed
            html += "</div>";
        });

                // Add plain-English explanation section
        html += "<div id='rf_explanations' style='margin-top:16px;padding:14px;background:#0a1525;border-radius:8px;border:1px solid #3ad29f'>";
        html += "<div style='color:#3ad29f;font-size:14px;font-weight:bold;margin-bottom:10px'>&#9654; What These Predictions Mean (Plain English Explanation)</div>";
        brief.ranked_predictions.slice(0, 3).forEach(function(move, idx) {
            var pct = Math.round((move.probability || 0) * 100);
            var tactic = move.tactic || "Unknown";
            var tname = move.technique_name || "Unknown";
            var tid = move.technique_id || "?";
            var reason = move.reasoning || "No reasoning provided";
            var action = move.defender_action || "Hunt for indicators of this technique";
            // spl removed
            html += "<div style='margin:8px 0;padding:10px;background:#0f3460;border-radius:6px;border-left:3px solid " + (idx===0?"#FF0000":idx===1?"#f5a623":"#3ad29f") + "'>";
            html += "<div style='color:" + (idx===0?"#FF0000":idx===1?"#f5a623":"#3ad29f") + ";font-weight:bold;font-size:14px'>#" + (idx+1) + " " + tid + " " + tname + " (" + pct + "% probability)</div>";
            html += "<div style='color:#a78bfa;font-size:12px;margin:4px 0'>MITRE Tactic: " + tactic + "</div>";
            html += "<div style='color:#fff;font-size:12px;margin:4px 0;line-height:1.5'>" + reason + "</div>";
            html += "<div style='color:#f5a623;font-size:11px;margin-top:6px'>&#9888; <b>What the defender should do:</b> " + action + "</div>";
            // spl removed
            html += "</div>";
        });
        html += "</div>";

        container.html(html);
    }

    // Trigger Signal Action
    $(document).on("click", "#rf_trigger_btn", function(e) {
        e.preventDefault();
        var scenario = $("#rf_scenario").val();
        var s = SCENARIOS[scenario] || SCENARIOS.t1003_001;
        var activePort = getApiPort();
        var targetApiUrl = getApiBaseUrl();

        var payload = {
            host: $("#rf_host").val() || s.host || "BSTOLL-L",
            source_ip: s.source_ip || "10.0.0.5",
            event_type: s.event_type,
            raw_event: $("#rf_raw").val() || s.raw,
            severity: s.sev || $("#rf_severity").val() || "high",
            splunk_index: "botsv3",
            additional_context: { scenario: scenario, source_ip: s.source_ip, host: s.host }
        };

        // Reset UI
        $("#rf_terminal").empty();
        $("#rf_predictions").empty();
        updatePipelineSteps(1, false);
        status("Connecting to Agent API on port " + activePort + "...", "#FFBF00");
        appendTerminalLine("Dispatching attack signal from host " + (s.host||"target") + " to FastAPI on port " + activePort + "...", "agent");

        $.ajax({
            url: targetApiUrl + "/trigger",
            type: "POST",
            contentType: "application/json",
            headers: { "X-API-Key": getApiKey() },
            data: JSON.stringify(payload),
            timeout: 5000,
            success: function(resp) {
                status("Signal accepted (task_id: " + resp.task_id.substring(0,8) + "). Agent thinking live...", "#3ad29f");
                appendTerminalLine("Signal accepted. Task ID: " + resp.task_id + ". Streaming agent thinking...", "info");

                // Notify Graph Visualizer on ports 8081 / 8082 if active
                var clientHost = window.location.hostname || "127.0.0.1";
                [8081, 8082].forEach(function(p) {
                    $.ajax({
                        url: "http://" + clientHost + ":" + p + "/notify",
                        type: "POST",
                        contentType: "application/json",
                        data: JSON.stringify({ task_id: resp.task_id, signal: payload }),
                        timeout: 2000,
                        error: function() {}
                    });
                });

                pollTask(resp.task_id, targetApiUrl);
            },
            error: function(err) {
                var errDetail = (err.responseJSON && err.responseJSON.detail) || err.statusText || "Connection refused";
                status("Trigger failed on port " + activePort + ": " + errDetail + ". Check if FastAPI is running on :" + activePort, "#FF0000");
                appendTerminalLine("[ERROR] Connection to FastAPI failed on port " + activePort + ": " + errDetail, "warning");
                updatePipelineSteps(1, true);
            }
        });
    });

    function pollTask(taskId, targetApiUrl) {
        var attempts = 0;
        var printedLogsCount = 0;

        var iv = setInterval(function() {
            $.ajax({
                url: targetApiUrl + "/trigger/status/" + taskId,
                type: "GET",
                headers: { "X-API-Key": getApiKey() },
                timeout: 3000,
                success: function(data) {
                    attempts++;
                    var currentStep = data.current_step || 1;
                    var logs = data.logs || [];

                    // Print newly arrived logs
                    while (printedLogsCount < logs.length) {
                        appendTerminalLine(logs[printedLogsCount], "agent");
                        printedLogsCount++;
                    }

                    // Update pipeline indicators
                    updatePipelineSteps(currentStep, data.status === "failed");

                    if (data.status === "completed") {
                        clearInterval(iv);
                        updatePipelineSteps(6, false);
                        var brief = data.brief;
                        var top = brief && brief.top_prediction;
                        var topMsg = top ? top.technique_id + " (" + Math.round(top.probability * 100) + "%)" : "None";
                        status("Agent prediction complete! Top TTP: " + topMsg, "#3ad29f");
                        appendTerminalLine("[SUCCESS] Reasoning & prediction graph complete. Brief generated.", "agent");
                        renderPredictions(brief);
                        fetchHealth();
                    } else if (data.status === "failed") {
                        clearInterval(iv);
                        status("Agent pipeline failed: " + (data.error || "unknown error"), "#FF0000");
                        appendTerminalLine("[FAILURE] Agent error: " + (data.error || "unknown"), "warning");
                    } else if (attempts > 40) {
                        clearInterval(iv);
                        status("Timed out waiting for agent task completion.", "#FFBF00");
                        appendTerminalLine("[WARN] Agent task polling timed out.", "warning");
                    } else {
                        status("Agent live thinking... Step " + currentStep + "/6 [" + (data.step_name || "Running") + "]", "#FFBF00");
                    }
                },
                error: function(err) {
                    attempts++;
                    if (attempts > 10) {
                        clearInterval(iv);
                        status("Lost connection while polling task status.", "#FF0000");
                    }
                }
            });
        }, 1500);
    }

    $(document).on("click", "#submitFeedbackBtn", function(e) {
        e.preventDefault();
        var ep = $("#episode_id").val();
        var ttp = $("#technique_id").val();
        var outcome = $("#outcome").val() === "true";
        if (!ep) { alert("Enter an Episode ID"); return; }
        $.ajax({
            url: getApiBaseUrl() + "/feedback",
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
            url: getApiBaseUrl() + "/feedback/episodes",
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
                $("#rf_episodes_body").html("<tr><td colspan='5' style='padding:10px;color:#FF0000'>FastAPI not reachable on port " + getApiPort() + "</td></tr>");
            }
        });
    }
    setTimeout(fetchEpisodes, 1500);
    setInterval(fetchEpisodes, 10000);

    // Initial probe to lock port 8081 if running
    probePorts();
});