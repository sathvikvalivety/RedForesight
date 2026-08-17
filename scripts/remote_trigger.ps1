# RedForesight Remote Trigger Script
# Run this from ANY laptop on the same network to simulate attacks
# against the RedForesight machine.
#
# Usage:  .\remote_trigger.ps1
# Or:     .\remote_trigger.ps1 -ServerIp 11.12.4.2 -Attack lsass
# Or:     .\remote_trigger.ps1 -ServerIp 11.12.4.2 -Attack ransomware

param(
    [string]$ServerIp = "11.12.4.2",
    [string]$ApiKey = "redforesight_demo_key_2026",
    [string]$Attack = "lsass"
)

$attacks = @{
    "lsass" = @{
        host = "ATTACKER-LAPTOP"
        source_ip = "192.168.1.99"
        event_type = "credential_access_attempt"
        raw_event = "Process rundll32.exe accessed lsass.exe memory with GrantedAccess 0x1010. Mimikatz credential dumping detected on endpoint. Parent process cmd.exe running as SYSTEM."
        severity = "critical"
    }
    "ransomware" = @{
        host = "ATTACKER-LAPTOP"
        source_ip = "192.168.1.99"
        event_type = "impact_attempt"
        raw_event = "Ransomware detected: vssadmin delete shadows all executed. Mass file encryption with .locked extension. 12000 files encrypted. Ransom note dropped demanding 50 BTC."
        severity = "critical"
    }
    "psexec" = @{
        host = "ATTACKER-LAPTOP"
        source_ip = "192.168.1.99"
        event_type = "lateral_movement_attempt"
        raw_event = "PsExec execution detected: services.exe spawned psexesvc.exe targeting remote host CORP-DC-01. Admin share accessed using stolen credentials."
        severity = "critical"
    }
    "phishing" = @{
        host = "ATTACKER-LAPTOP"
        source_ip = "192.168.1.99"
        event_type = "initial_access_attempt"
        raw_event = "Phishing email with malicious macro document opened. WINWORD.EXE spawned powershell.exe with encoded payload. Parent chain: outlook to winword to powershell."
        severity = "high"
    }
    "log4shell" = @{
        host = "ATTACKER-LAPTOP"
        source_ip = "192.168.1.99"
        event_type = "initial_access_attempt"
        raw_event = "Exploit attempt against web server. Log4Shell JNDI lookup payload in HTTP header. Tomcat made outbound LDAP connection to attacker server."
        severity = "critical"
    }
    "dcsync" = @{
        host = "ATTACKER-LAPTOP"
        source_ip = "192.168.1.99"
        event_type = "credential_access_attempt"
        raw_event = "DCSync attack. LSASS processed DRSUAPI replication from non-DC host. Replicating Directory Changes permission abused to extract all domain password hashes."
        severity = "critical"
    }
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  RedForesight Remote Attack Trigger" -ForegroundColor Cyan
Write-Host "  Server: $ServerIp:8080" -ForegroundColor Cyan
Write-Host "  Available attacks:" -ForegroundColor Cyan
$attacks.Keys | ForEach-Object { Write-Host "    - $_" }
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$attack = $attacks[$Attack]
if (-not $attack) {
    Write-Host "Unknown attack: $Attack" -ForegroundColor Red
    Write-Host "Available: $($attacks.Keys -join ', ')"
    exit 1
}

$body = @{
    host = $attack.host
    source_ip = $attack.source_ip
    event_type = $attack.event_type
    raw_event = $attack.raw_event
    severity = $attack.severity
    splunk_index = "botsv3"
    additional_context = @{}
} | ConvertTo-Json -Compress

Write-Host "Firing attack: $Attack from $($attack.host) ($($attack.source_ip))..." -ForegroundColor Yellow
try {
    $r = Invoke-RestMethod -Uri "http://${ServerIp}:8080/api/v1/trigger" -Method Post -Headers @{"Content-Type"="application/json";"X-API-Key"=$ApiKey} -Body $body -TimeoutSec 15
    Write-Host "Signal accepted! Task ID: $($r.task_id)" -ForegroundColor Green
    Write-Host "Waiting for prediction..." -ForegroundColor Yellow
    
    for ($i = 1; $i -le 15; $i++) {
        Start-Sleep 3
        $st = Invoke-RestMethod -Uri "http://${ServerIp}:8080/api/v1/trigger/status/$($r.task_id)" -Headers @{"X-API-Key"=$ApiKey} -TimeoutSec 10
        if ($st.status -ne "running") { break }
        Write-Host "  Agent running... ($i)"
    }
    
    if ($st.status -eq "completed") {
        Write-Host ""
        Write-Host "=== PREDICTION COMPLETE ===" -ForegroundColor Green
        Write-Host "Detected Tactic: $($st.brief.tactic_classification)" -ForegroundColor Cyan
        Write-Host "Host: $($st.brief.splunk_context.host)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Top Prediction:" -ForegroundColor Yellow
        Write-Host "  Technique: $($st.brief.top_prediction.technique_id) - $($st.brief.top_prediction.technique_name)"
        Write-Host "  Probability: $([math]::Round($st.brief.top_prediction.probability * 100, 1))%"
        Write-Host "  Confidence: $($st.brief.top_prediction.confidence_tier)"
        Write-Host "  Reasoning: $($st.brief.top_prediction.reasoning)"
        Write-Host ""
        Write-Host "SPL Hunting Query:" -ForegroundColor Yellow
        Write-Host "  $($st.brief.top_prediction.splunk_hunting_query)"
        Write-Host ""
        Write-Host "All Predictions:" -ForegroundColor Yellow
        foreach ($p in $st.brief.ranked_predictions) {
            Write-Host "  $($p.technique_id) - $($p.technique_name) ($([math]::Round($p.probability * 100, 1))%)"
        }
    } else {
        Write-Host "Status: $($st.status)" -ForegroundColor Red
        if ($st.error) { Write-Host "Error: $($st.error)" -ForegroundColor Red }
    }
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Make sure the server IP is correct and RedForesight FastAPI is running on :8080"
}
