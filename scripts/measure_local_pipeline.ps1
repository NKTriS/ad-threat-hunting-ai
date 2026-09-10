$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$metricsPath = Join-Path $repoRoot "data\runtime_metrics.json"

function Get-TrackedWorkingSetBytes {
    param([Parameter(Mandatory = $true)][int]$PythonProcessId)

    $processes = @(
        Get-Process -Id $PythonProcessId -ErrorAction SilentlyContinue
        Get-Process -Name "ollama*" -ErrorAction SilentlyContinue
    )
    $sum = ($processes | Measure-Object -Property WorkingSet64 -Sum).Sum
    if ($null -eq $sum) { return 0 }
    return [double]$sum
}

function Get-GpuMemoryMb {
    $nvidiaSmi = Get-Command nvidia-smi -ErrorAction SilentlyContinue
    if ($null -eq $nvidiaSmi) { return $null }

    $lines = & $nvidiaSmi.Source --query-gpu=memory.used --format=csv,noheader,nounits 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    $values = @(
        $lines | ForEach-Object {
            $parsed = 0.0
            if ([double]::TryParse($_.Trim(), [ref]$parsed)) { $parsed }
        }
    )
    if ($values.Count -eq 0) { return $null }
    return [double](($values | Measure-Object -Sum).Sum)
}

function Get-OllamaAllocation {
    try {
        $response = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/ps" -TimeoutSec 2
    }
    catch {
        return $null
    }

    $models = @($response.models)
    if ($models.Count -eq 0) { return $null }
    $totalBytes = [double](($models | Measure-Object -Property size -Sum).Sum)
    $vramBytes = [double](($models | Measure-Object -Property size_vram -Sum).Sum)
    return [pscustomobject]@{
        total_bytes = $totalBytes
        cpu_bytes = [math]::Max(0, $totalBytes - $vramBytes)
        vram_bytes = $vramBytes
    }
}

function Invoke-MeteredPython {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $quotedArguments = $Arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + $_.Replace('"', '\"') + '"' } else { $_ }
    }
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = "python"
    $startInfo.Arguments = $quotedArguments -join " "
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not $process.Start()) { throw "Could not start $Name" }
    $peakRamBytes = 0.0
    $peakGpuMb = $null
    $peakModelTotalBytes = 0.0
    $peakModelCpuBytes = 0.0
    $peakModelVramBytes = 0.0

    do {
        $ramBytes = Get-TrackedWorkingSetBytes -PythonProcessId $process.Id
        if ($ramBytes -gt $peakRamBytes) { $peakRamBytes = $ramBytes }

        $gpuMb = Get-GpuMemoryMb
        if ($null -ne $gpuMb -and ($null -eq $peakGpuMb -or $gpuMb -gt $peakGpuMb)) {
            $peakGpuMb = $gpuMb
        }

        $allocation = Get-OllamaAllocation
        if ($null -ne $allocation) {
            $peakModelTotalBytes = [math]::Max($peakModelTotalBytes, $allocation.total_bytes)
            $peakModelCpuBytes = [math]::Max($peakModelCpuBytes, $allocation.cpu_bytes)
            $peakModelVramBytes = [math]::Max($peakModelVramBytes, $allocation.vram_bytes)
        }
        Start-Sleep -Milliseconds 500
        $process.Refresh()
    } while (-not $process.HasExited)

    $process.WaitForExit()
    $stdout = $process.StandardOutput.ReadToEnd().Trim()
    $stderr = $process.StandardError.ReadToEnd().Trim()
    $process.Refresh()
    $exitCode = $process.ExitCode
    $timer.Stop()
    if ($null -eq $exitCode) {
        throw "$Name finished but Windows did not return an exit code"
    }
    if ($exitCode -ne 0) {
        throw "$Name failed with exit code $exitCode`n$stderr"
    }
    if ($stdout) { [Console]::WriteLine($stdout) }

    return [pscustomobject]@{
        name = $Name
        elapsed_seconds = [math]::Round($timer.Elapsed.TotalSeconds, 3)
        peak_process_working_set_mb = [math]::Round($peakRamBytes / 1MB, 1)
        peak_gpu_used_mb = if ($null -eq $peakGpuMb) { $null } else { [math]::Round($peakGpuMb, 1) }
        peak_model_total_mb = [math]::Round($peakModelTotalBytes / 1MB, 1)
        peak_model_cpu_mb = [math]::Round($peakModelCpuBytes / 1MB, 1)
        peak_model_vram_mb = [math]::Round($peakModelVramBytes / 1MB, 1)
    }
}

Push-Location $repoRoot
try {
    $results = @(
        Invoke-MeteredPython -Name "correlate" -Arguments @(
            "-m", "ai.cli", "correlate",
            "--alerts", "data/sample_alerts.jsonl",
            "--output", "data/incidents.json"
        )
        Invoke-MeteredPython -Name "build_index" -Arguments @("-m", "ai.cli", "build-index")
        Invoke-MeteredPython -Name "analyze_rag" -Arguments @("-m", "ai.cli", "analyze")
        Invoke-MeteredPython -Name "analyze_no_rag" -Arguments @(
            "-m", "ai.cli", "analyze", "--no-rag"
        )
        Invoke-MeteredPython -Name "evaluate" -Arguments @(
            "-m", "ai.cli", "evaluate",
            "--baseline-reports", "data/reports_no_rag.json"
        )
    )

    $computer = Get-CimInstance Win32_ComputerSystem
    $payload = [ordered]@{
        measured_at = [DateTimeOffset]::Now.ToString("o")
        machine_ram_gb = [math]::Round($computer.TotalPhysicalMemory / 1GB, 2)
        note = "Working set covers pipeline Python/Ollama. Model allocation comes from Ollama /api/ps. GPU used is whole-device usage."
        runs = $results
    }
    $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $metricsPath -Encoding utf8
    Write-Output "Wrote runtime metrics to $metricsPath"
    $results | Format-Table -AutoSize
}
finally {
    Pop-Location
}
