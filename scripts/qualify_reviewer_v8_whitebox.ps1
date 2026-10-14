param(
    [string]$Zip = (Join-Path $env:USERPROFILE "Downloads/reviewer-v8-whitebox-submission.zip"),
    [string]$Archive = (Join-Path $env:USERPROFILE "Downloads/csce704-blackbox-validation-100-samples-20261014.zip"),
    [string]$Image = "blackbox-defense:v8-whitebox-rescue"
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
foreach ($path in @($Zip, $Archive)) {
    if (-not (Test-Path $path -PathType Leaf)) { throw "File not found: $path. Pass its actual path using -Zip or -Archive." }
}
$Zip = (Resolve-Path $Zip).Path
$Archive = (Resolve-Path $Archive).Path
$expected = Get-Content -Raw (Join-Path $repo "submission/whitebox-package.json") | ConvertFrom-Json
$zipSha = (Get-FileHash -Algorithm SHA256 $Zip).Hash.ToLowerInvariant()
if ($zipSha -ne $expected.zip_sha256) { throw "ZIP hash does not match the prepared whitebox package." }
$work = Join-Path $repo ("validation-data/whitebox-submission-" + (Get-Date -Format "yyyyMMdd-HHmmss-ffff"))
$context = Join-Path $work "context"
New-Item -ItemType Directory -Path $context -Force | Out-Null
Expand-Archive -LiteralPath $Zip -DestinationPath $context
$buildOut = Join-Path $work "docker-build.stdout.log"
$buildErr = Join-Path $work "docker-build.stderr.log"
function Invoke-Docker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed: $($Arguments -join ' ')" }
}
Write-Host "Clean-building the standalone whitebox ZIP. Reports: $work"
$clock = [System.Diagnostics.Stopwatch]::StartNew()
$build = Start-Process -FilePath "docker" -ArgumentList @("build", "--pull", "--no-cache", "-t", $Image, ('"' + $context + '"')) -NoNewWindow -PassThru -RedirectStandardOutput $buildOut -RedirectStandardError $buildErr
$buildHandle = $build.Handle
if (-not $build.WaitForExit(300000)) { $build.Kill(); throw "Clean build exceeded 300 seconds. Logs: $work" }
$build.WaitForExit()
$buildSeconds = $clock.Elapsed.TotalSeconds
if ($null -eq $build.ExitCode -or $build.ExitCode -ne 0 -or $buildSeconds -gt 300) {
    Get-Content $buildErr | Write-Host
    throw "Clean build failed or exceeded 300 seconds. Logs: $work"
}
$imageId = (Invoke-Docker -Arguments @("image", "inspect", $Image, "--format", "{{.Id}}")).Trim()
$name = "whitebox-qualified-" + (Get-Date -Format "yyyyMMdd-HHmmss-ffff")
$container = $null
try {
    $clock.Restart()
    $container = (Invoke-Docker -Arguments @("run", "-d", "--name", $name, "--network", "none", "--read-only",
        "--memory", "1g", "--cpus", "1", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--mount", "type=bind,source=$repo/scripts,target=/checks,readonly",
        "--mount", "type=bind,source=$Archive,target=/tests/ta-samples.zip,readonly", $Image)).Trim()
    $ready = $false
    while ($clock.Elapsed.TotalSeconds -lt 25) {
        & docker exec $container python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=1)" 2>$null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw "Restricted startup exceeded 25 seconds" }
    $startup = $clock.Elapsed.TotalSeconds
    Invoke-Docker -Arguments @("exec", $container, "python", "-c", "import os; assert os.getuid()!=0")
    $publicOutput = & docker exec $container python /checks/check_whitebox_submission_public.py --archive /tests/ta-samples.zip
    $publicExit = $LASTEXITCODE
    $publicOutput | Set-Content -Encoding UTF8 (Join-Path $work "whitebox-public-api-summary.json")
    if ($publicExit -ne 0) { throw "Standalone public API check failed; inspect whitebox-public-api-summary.json" }
    $public = ($publicOutput -join "`n") | ConvertFrom-Json
    $usage = Invoke-Docker -Arguments @("exec", $container, "python", "-c",
        "import json; from pathlib import Path; s=Path('/proc/1/status').read_text(); fields={line.split(':')[0]:line.split(':',1)[1].strip() for line in s.splitlines() if line.startswith(('VmRSS:','VmHWM:'))}; paths=[Path('/sys/fs/cgroup/memory.peak'),Path('/sys/fs/cgroup/memory/memory.max_usage_in_bytes')]; p=next((p for p in paths if p.is_file()),None); print(json.dumps(dict(process=fields,cgroup_peak_bytes=int(p.read_text()) if p else None)))")
    $resources = ($usage -join "`n") | ConvertFrom-Json
    $inspect = ((Invoke-Docker -Arguments @("inspect", $container)) -join "`n" | ConvertFrom-Json)[0]
    if ($inspect.State.OOMKilled -or $inspect.Image -ne $imageId -or
        $inspect.HostConfig.Memory -ne 1073741824 -or $inspect.HostConfig.NanoCpus -ne 1000000000 -or
        -not $inspect.HostConfig.ReadonlyRootfs -or $inspect.HostConfig.NetworkMode -ne "none") {
        throw "Restricted container configuration/image check failed"
    }
    $processPeakKiB = [long](($resources.process.VmHWM -split ' ')[0])
    if ($processPeakKiB -ge 1048576 -or
        ($null -ne $resources.cgroup_peak_bytes -and $resources.cgroup_peak_bytes -ge 1073741824)) {
        throw "Measured memory reaches the 1 GiB cap"
    }
    if (-not $public.passed) { throw "Public-API report did not pass" }
    $summary = [ordered]@{
        complete = $true; standalone_runtime_qualified = $true; zip_name = (Split-Path -Leaf $Zip)
        zip_sha256 = $zipSha; image_id = $imageId; clean_build_seconds = $buildSeconds
        restricted_startup_seconds = $startup; diagnostics_disabled = $true
        malware_detected = $public.malware_detected; benign_correct = $public.benign_correct
        errors = $public.errors; max_public_http_seconds = $public.max_public_http_seconds
        resources = $resources; memory_limit_bytes = $inspect.HostConfig.Memory
        nano_cpus = $inspect.HostConfig.NanoCpus; readonly = $inspect.HostConfig.ReadonlyRootfs
        network = $inspect.HostConfig.NetworkMode; oom_killed = $inspect.State.OOMKilled
        course_base_pin_confirmed = $false
        scope = "Exact standalone ZIP; disclosed TA tuning set; test inputs mounted read-only, inference code/models bundled in image."
    }
    $summary | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 (Join-Path $work "whitebox-submission-qualification.json")
    Write-Host "PASS. Send: $(Join-Path $work 'whitebox-submission-qualification.json')"
    Write-Host "The ZIP remains at $Zip. No external submission has been sent."
} catch {
    if ($container) { & docker logs --tail 60 $container | Out-Host }
    Write-Host "Failure reports retained at $work"
    throw
} finally {
    if ($container) { & docker stop $container | Out-Host }
}
