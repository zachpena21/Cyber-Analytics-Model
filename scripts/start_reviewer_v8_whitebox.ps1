param(
    [string]$Archive = (Join-Path $env:USERPROFILE "Downloads/csce704-blackbox-validation-100-samples-20261014.zip"),
    [string]$Image = "blackbox-defense:v8-final",
    [int]$Port = 8084
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$candidate = Join-Path $repo "defender/defender/models/boundary_reviewer_v8_whitebox_t060"
if (-not (Test-Path $Archive -PathType Leaf)) { throw "Archive not found: $Archive. Pass -Archive with its actual ZIP path." }
$Archive = (Resolve-Path $Archive).Path
$work = Join-Path $repo ("validation-data/whitebox-v8-t060-" + (Get-Date -Format "yyyyMMdd-HHmmss-ffff"))
New-Item -ItemType Directory -Path $work | Out-Null
function Invoke-Docker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed: $($Arguments -join ' ')" }
}
Invoke-Docker -Arguments @("image", "inspect", $Image, "--format", "{{.Id}}")
$occupied = Invoke-Docker -Arguments @("ps", "-q", "--filter", "publish=$Port")
if ($occupied) { throw "Port $Port is occupied; pass -Port with another free port." }
$name = "v8-whitebox-t060-" + (Get-Date -Format "yyyyMMdd-HHmmss-ffff")
Invoke-Docker -Arguments @("run", "-d", "--name", $name, "--read-only", "--memory", "1g", "--cpus", "1",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "-p", "${Port}:8080",
    "-e", "DF_ENABLE_SCORE_ENDPOINT=1",
    "--mount", "type=bind,source=$repo/scripts,target=/checks,readonly",
    "--mount", "type=bind,source=$candidate,target=/candidate,readonly",
    "--mount", "type=bind,source=$Archive,target=/input/ta-samples.zip,readonly",
    "--mount", "type=bind,source=$work,target=/proof",
    "--entrypoint", "python", $Image, "/checks/serve_reviewer_v8_whitebox.py", "--model", "/candidate/model.json")
Write-Host "Candidate container: $name; port: $Port"
$ready = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    try {
        $info = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/model" -TimeoutSec 2
        $ready = $true
        break
    } catch { Start-Sleep -Seconds 1 }
}
if (-not $ready) {
    & docker logs --tail 60 $name
    throw "Candidate startup failed. Reports: $work. Container retained for inspection."
}
if (-not $info.score_endpoint_enabled -or -not $info.boundary_reviewer -or
    $info.reviewer_threshold -ne 0.60 -or $info.reviewer_route_min -ne 0.15) {
    throw "Candidate loaded an unexpected policy; inspect docker logs $name"
}
Invoke-Docker -Arguments @("exec", $name, "python", "/checks/score_reviewer_v8_whitebox.py",
    "--archive", "/input/ta-samples.zip", "--model", "/candidate/model.json",
    "--service-url", "http://127.0.0.1:8080", "--output-prefix", "/proof/whitebox-v8-t060")
$report = Get-Content -Raw (Join-Path $work "whitebox-v8-t060.json") | ConvertFrom-Json
if (-not $report.complete -or $report.errors -ne 0 -or
    $report.true_positives -ne 49 -or $report.true_negatives -ne 50) {
    throw "Runtime differs from the cached 49/50 malware, 50/50 benign result. Inspect $work."
}
Write-Host "PASS: actual Docker results match cached replay: 49/50 malware, 50/50 benign."
Write-Host "Send: $(Join-Path $work 'whitebox-v8-t060.json')"
Write-Host "Candidate remains running on port $Port; stop with: docker stop $name"
