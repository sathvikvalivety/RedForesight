require([
    "jquery",
    "splunkjs/mvc",
    "splunkjs/mvc/simplexml/ready!"
], function($, mvc) {
    console.log("RedForesight feedback.js loaded");

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
        // ---- Privilege Escalation ----
        t1548_002: { event_type: "privilege_escalation_attempt", sev: "high", host: "CORP-SQL-01", source_ip: "185.220.101.45", raw: "UAC bypass detected. fodhelper.exe launched with elevated privileges. Registry key ms-settings Shell Open command modified to point to custom executable. Auto-elevate set to 1. Fodhelper runs elevated and executes hijacked command. This is T1548.002 Bypass User Account Control." },
        t1068: { event_type: "privilege_escalation_attempt", sev: "critical", host: "CORP-SQL-01", source_ip: "10.0.0.12", raw: "Exploitation for privilege escalation. RoguePotato exploit detected. DCOM activation abuse leveraging SeImpersonatePrivilege. Printspooler service pipe impersonation to gain SYSTEM token. Process running as service account escalated to NT AUTHORITY SYSTEM. This is T1068 Exploitation for Privilege Escalation." },
        // ---- Defense Evasion ----
        t1027: { event_type: "defense_evasion_attempt", sev: "high", host: "CORP-WS-31", source_ip: "91.240.118.20", raw: "Obfuscated files or information. PowerShell script with heavy obfuscation detected: base64 encoded strings, variable name randomization, string concatenation to avoid signatures. Script content uses multiple layers of encoding including XOR. This is T1027 Obfuscated Files or Information." },
        t1562_001: { event_type: "defense_evasion_attempt", sev: "critical", host: "BSTOLL-L", source_ip: "10.0.0.12", raw: "Disable tools. Windows Defender real-time protection disabled via Set-MpPreference DisableRealtimeMonitoring. Executed by non-admin user via UAC bypass. Defender service disabled for 4 hours. Malware downloaded and executed during disabled window. This is T1562.001 Disable or Modify Tools." },
        // ---- Credential Access ----
        t1003_001: { event_type: "credential_access_attempt", sev: "critical", host: "CORP-DC-02", source_ip: "192.168.2.25", raw: "LSASS memory access. Process rundll32.exe accessed lsass.exe memory with GrantedAccess 0x1010. This access mask is consistent with credential dumping tools including Mimikatz. Source host BSTOLL-L. Sysmon EventCode 10 captured the process access. Parent process cmd.exe running as SYSTEM. This is T1003.001 LSASS Memory." },
        t1003_006: { event_type: "credential_access_attempt", sev: "critical", host: "CORP-DC-02", source_ip: "10.2.5.14", raw: "DCSync attack. LSASS.exe processed DRSUAPI replication request from non-DC host. User account with Replicating Directory Changes permission abused to extract all domain password hashes. 347 user hashes exfiltrated. This is T1003.006 DCSync." },
        // ---- Discovery ----
        t1087_001: { event_type: "discovery_attempt", sev: "low", host: "CORP-WS-12", source_ip: "10.0.2.18", raw: "Account discovery. net user domain and net group Domain Admins domain executed by non-admin user. Enumerating all domain accounts and privileged groups. Followed by net localgroup administrators on local host. This is T1087.001 Local Account discovery." },
        t1018: { event_type: "discovery_attempt", sev: "low", host: "CORP-WS-22", source_ip: "192.168.1.45", raw: "Remote system discovery. nmap scan detected: scanning entire internal subnet for SMB, RDP, WinRM services. 47 hosts found alive. Executed from compromised host BSTOLL-L. This is T1018 Remote System Discovery." },
        // ---- Lateral Movement ----
        t1021_001: { event_type: "lateral_movement_attempt", sev: "critical", host: "CORP-FILE-01", source_ip: "10.0.0.12", raw: "Remote desktop protocol lateral movement. RDP connection from 10.0.0.5 to DC01. EventCode 4624 LogonType 10. Source IP has no prior RDP history to this host. Session lasted 45 minutes. Attacker used stolen admin credentials. This is T1021.001 Remote Desktop Protocol." },
        t1021_002: { event_type: "lateral_movement_attempt", sev: "critical", host: "CORP-SQL-01", source_ip: "192.168.1.45", raw: "SMB Windows Admin Shares lateral movement. PsExec execution detected: services.exe spawned psexesvc.exe on remote host CORP-DC-01. Admin share ADMIN$ accessed from source. PSEXESVC service created and started on target. This is T1021.002 SMB Windows Admin Shares." },
        // ---- Collection ----
        t1005: { event_type: "collection_attempt", sev: "medium", host: "CORP-WS-07", source_ip: "91.240.118.20", raw: "Data from local system. Mass file access detected: 4200 document files accessed in Users Public and shared drives. Accessed by non-owner process powershell.exe. Files indexed and catalogued for selective exfiltration. This is T1005 Data from Local System." },
        // ---- Command and Control ----
        t1071_001: { event_type: "c2_communication", sev: "high", host: "CORP-PROXY-01", source_ip: "10.0.3.55", raw: "Web service C2. DNS tunneling detected. Anomalous TXT query volume to attacker domain. 847 queries in 60s. Beacon pattern consistent with Cobalt Strike DNS beacon. Data exfiltrated via TXT record responses. This is T1071.001 Web Protocols." },
        // ---- Exfiltration ----
        t1041: { event_type: "exfiltration_attempt", sev: "critical", host: "CORP-DB-02", source_ip: "10.0.0.45", raw: "Exfiltration over C2 channel. 2.3GB uploaded to attacker server over 4 hours via HTTPS. Connection established after data collection script completed. Destination has no prior history. Data includes financial records and customer PII. This is T1041 Exfiltration Over C2 Channel." },
        // ---- Impact ----
        t1486: { event_type: "impact_attempt", sev: "critical", host: "CORP-SQL-01", source_ip: "185.220.101.45", raw: "Data encrypted for impact. Ransomware detected: vssadmin delete shadows all executed. Then mass file encryption of all drives. .encrypted extension applied to 48000 files. Ransom note dropped in every directory demanding 50 BTC. This is T1486 Data Encrypted for Impact." }
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

    function appendTerminalLine(msg, type) {
        var term = $("#rf_terminal");
        if (!term.length) return;
        var timeStr = new Date().toLocaleTimeString();
        var cls = type || "info";
        var lineHtml = "<div class=\"line " + cls + "\">[" + timeStr + "] " + msg + "</div>";
        term.append(lineHtml);
        term.scrollTop(term[0].scrollHeight);

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
            if (move.splunk_hunting_query) {
                html += "  <div style=\"margin-top:6px;background:#0a0e14;padding:8px;border:1px solid #33415c;border-radius:4px;font-family:monospace;font-size:11px;color:#3ad29f\">";
                html += "    <b>SPL Hunt Query:</b> <code>" + move.splunk_hunting_query + "</code>";
                html += "  </div>";
            }
            html += "</div>";
        });

        container.html(html);
    }

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

                    while (printedLogsCount < logs.length) {
                        appendTerminalLine(logs[printedLogsCount], "agent");
                        printedLogsCount++;
                    }

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

    probePorts();
});
