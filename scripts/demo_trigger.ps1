$signal = Get-Content data\sample_signals\demo_signal.json -Raw
$response = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/v1/trigger" `
  -Method Post `
  -Headers @{"Content-Type"="application/json"} `
  -Body $signal

Write-Host "Task ID: $($response.task_id)"
Write-Host "Signal ID: $($response.signal_id)"

$max_attempts = 20
for ($i=1; $i -le $max_attempts; $i++) {
    Start-Sleep 2
    $status = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/v1/trigger/status/$($response.task_id)" -Method Get
    if ($status.status -ne "running") {
        break
    }
}

Write-Host "Status: $($status.status)"
if ($status.status -eq "completed") {
    Write-Host "Top technique: $($status.brief.top_prediction.technique_id)"
    Write-Host "Probability: $($status.brief.top_prediction.probability)"
} else {
    Write-Host "Error: Task did not complete in time or failed. Final status: $($status.status)"
}
