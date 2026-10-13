param(
    [string]$LegacyImage = "blackbox-defense:v7-reference",
    [string]$Image = "blackbox-defense:v8-final",
    [string]$ReferenceUrl = "http://host.docker.internal:8082",
    [int]$DiagnosticPort = 8083
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$stamp = Get-Date -Format "yyyyMMdd-HHmmss-ffff"
$work = Join-Path $repo "validation-data/submission-v8-$stamp"
New-Item -ItemType Directory -Path $work | Out-Null
$artifacts = Join-Path $work "artifacts"
New-Item -ItemType Directory -Path (Join-Path $artifacts "compact") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $artifacts "modern_adapter") -Force | Out-Null
function Invoke-Docker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed: $($Arguments -join ' ')" }
}
$source = $null
$restricted = $null
$diagnostic = $null
try {
    Invoke-Docker -Arguments @("image", "inspect", $LegacyImage, "--format", "{{.Id}}")
    $source = (Invoke-Docker -Arguments @("create", "--entrypoint", "/bin/true", $LegacyImage)).Trim()
    Invoke-Docker -Arguments @("cp", "${source}:/opt/defender/defender/models/compact/.", (Join-Path $artifacts "compact"))
    Invoke-Docker -Arguments @("cp", "${source}:/opt/defender/defender/models/modern_adapter/.", (Join-Path $artifacts "modern_adapter"))
    Invoke-Docker -Arguments @("run", "--rm", "--network", "none", "--read-only", "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-v", "${repo}/scripts:/checks:ro", "-v", "${repo}/defender/defender/models/portable_pipeline.py:/checks-portable.py:ro",
        "-v", "${artifacts}/compact:/output", "--entrypoint", "python", $LegacyImage,
        "/checks/export_submission_pipeline.py", "--input", "/opt/defender/defender/models/compact/feature_pipeline.pkl.gz",
        "--output", "/output/feature-pipeline.json", "--module", "/checks-portable.py")
    Invoke-Docker -Arguments @("run", "--rm", "--network", "none", "--read-only", "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-v", "${repo}:/repo:ro", "-v", "${work}:/work", "--entrypoint", "python", $LegacyImage,
        "/repo/scripts/prepare_reviewer_v8_submission.py", "--repo", "/repo", "--artifacts", "/work/artifacts", "--output", "/work/context")
    $context = Join-Path $work "context"
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $buildOut = Join-Path $work "docker-build.stdout.log"
    $buildErr = Join-Path $work "docker-build.stderr.log"
    Write-Host "Building image (up to 300 seconds). Live build log: $buildErr"
    $build = Start-Process -FilePath "docker" -ArgumentList @("build", "--pull", "--no-cache", "-t", $Image, ('"' + $context + '"')) -NoNewWindow -PassThru -RedirectStandardOutput $buildOut -RedirectStandardError $buildErr
    # Retain the native handle before waiting: Windows PowerShell may otherwise
    # lose access to ExitCode for a process returned by Start-Process.
    $buildHandle = $build.Handle
    if (-not $build.WaitForExit(300000)) { $build.Kill(); throw "Clean build timed out at 300 seconds" }
    $build.WaitForExit()
    $buildExitCode = $build.ExitCode
    if (Test-Path $buildOut) { Get-Content $buildOut | ForEach-Object { Write-Host $_ } }
    if (Test-Path $buildErr) { Get-Content $buildErr | ForEach-Object { Write-Host $_ } }
    if ($null -eq $buildExitCode) { throw "Docker exit code unavailable; see docker-build.stdout.log and docker-build.stderr.log in $work" }
    if ($buildExitCode -ne 0) { throw "Docker build failed with exit code $buildExitCode; see docker-build.stderr.log in $work" }
    $buildSeconds = $clock.Elapsed.TotalSeconds
    if ($buildSeconds -gt 300) { throw "Clean build exceeded 300 seconds: $buildSeconds" }
    $restricted = (Invoke-Docker -Arguments @("run", "-d", "--name", "v8-restricted-$stamp", "--read-only", "--network", "none",
        "--memory", "1g", "--cpus", "1", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", $Image)).Trim()
    $clock.Restart()
    $ready = $false
    while ($clock.Elapsed.TotalSeconds -lt 25) {
        try {
            & docker exec $restricted python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=1)" 2>$null
            if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        } catch { }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { Invoke-Docker -Arguments @("logs", $restricted); throw "Restricted startup exceeded 25 seconds" }
    $startupSeconds = $clock.Elapsed.TotalSeconds
    Invoke-Docker -Arguments @("exec", $restricted, "python", "-c",
        "import json,os,urllib.request,urllib.error; assert os.getuid()!=0; d=json.load(urllib.request.urlopen('http://127.0.0.1:8080/model')); assert d['boundary_reviewer'] and not d['score_endpoint_enabled']; assert d['reviewer_route_min']==0.15 and d['reviewer_threshold']==0.6882517225516912; print(json.dumps(d))")
    Invoke-Docker -Arguments @("exec", $restricted, "python", "-c",
        "import urllib.request; r=urllib.request.Request('http://127.0.0.1:8080/diagnostics/score',data=b'MZ',headers={'Content-Type':'application/octet-stream'}); handler=type('NoRaise',(urllib.request.HTTPErrorProcessor,),{'http_response':lambda self,req,resp:resp}); opener=urllib.request.build_opener(handler()); assert opener.open(r).status==404")
    $occupied = & docker ps -q --filter "publish=$DiagnosticPort"
    if ($occupied) { throw "Port $DiagnosticPort is occupied. Use -DiagnosticPort with another free port." }
    $diagnostic = (Invoke-Docker -Arguments @("run", "-d", "--name", "v8-diagnostic-$stamp", "--read-only", "--memory", "1g", "--cpus", "1",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "-p", "${DiagnosticPort}:8080",
        "-e", "DF_ENABLE_SCORE_ENDPOINT=1", "-v", "${repo}/scripts:/checks:ro", "-v", "${env:WINDIR}/System32:/samples:ro",
        "-v", "${work}:/proof", $Image)).Trim()
    $clock.Restart();$ready = $false
    while ($clock.Elapsed.TotalSeconds -lt 25) {
        try {
            & docker exec $diagnostic python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=1)" 2>$null
            if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        } catch { }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw "Diagnostic startup failed" }
    $samples = @("kernel32.dll", "user32.dll", "advapi32.dll", "ntdll.dll", "kernelbase.dll", "crypt32.dll", "winhttp.dll", "ws2_32.dll",
        "msvcrt.dll", "ole32.dll", "oleaut32.dll", "shell32.dll", "gdi32.dll", "sechost.dll", "shlwapi.dll", "cmd.exe")
    $files = @($samples | Where-Object { Test-Path (Join-Path "$env:WINDIR/System32" $_) } | ForEach-Object { "/samples/$_" })
    Invoke-Docker -Arguments (@("exec", $diagnostic, "python", "/checks/check_reviewer_v8_runtime_parity.py",
        "--reference", $ReferenceUrl, "--candidate", "http://127.0.0.1:8080", "--model",
        "/opt/defender/defender/models/boundary_reviewer_v8_final/model.json", "--output", "/proof/runtime-parity-summary.json", "--files") + $files)
    $imageId = (Invoke-Docker -Arguments @("image", "inspect", $Image, "--format", "{{.Id}}")).Trim()
    @{ complete=$true; image=$Image; image_id=$imageId; clean_build_seconds=$buildSeconds; restricted_startup_seconds=$startupSeconds;
        restricted_network="none"; readonly=$true; nonroot=$true; cpus=1; memory_bytes=1073741824; diagnostics_disabled=$true;
        raw_pe_parity="See runtime-parity-summary.json; Windows benign smoke cohort only"; course_base_pin_confirmed=$false;
        submission_ready=$false; next="Broader benign/malware parity and latency/memory checks; confirm approved image pin before final ZIP" } |
        ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 (Join-Path $work "submission-preflight-summary.json")
    Write-Host "Preflight complete: $work"
    Write-Host "Send submission-preflight-summary.json and runtime-parity-summary.json. Final ZIP is pending broader runtime parity."
    Write-Host "Diagnostic container remains available on port $DiagnosticPort : $diagnostic"
    $diagnostic = $null
} catch {
    $_ | Out-String | Set-Content -Encoding UTF8 (Join-Path $work "preflight-error.txt")
    if ($restricted) { try { & docker logs $restricted 2>&1 | Out-File (Join-Path $work "restricted-container.log") } catch { } }
    if ($diagnostic) { try { & docker logs $diagnostic 2>&1 | Out-File (Join-Path $work "diagnostic-container.log") } catch { } }
    Write-Host "Preflight failed; reports/logs retained at $work"
    throw
} finally {
    foreach ($id in @($source,$restricted,$diagnostic)) {
        if ($id) { & docker rm -f $id | Out-Null }
    }
}
