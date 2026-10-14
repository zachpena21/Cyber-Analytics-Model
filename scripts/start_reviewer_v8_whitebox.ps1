param(
    [string]$Archive = (Join-Path $env:USERPROFILE "Downloads/csce704-blackbox-validation-100-samples-20261014.zip"),
    [string]$Image = "blackbox-defense:v8-final",
    [int]$Port = 8084,
    [switch]$AgreementRescue
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$candidate = Join-Path $repo "defender/defender/models/boundary_reviewer_v8_whitebox_t060"
if (-not (Test-Path $Archive -PathType Leaf)) { throw "Archive not found: $Archive. Pass -Archive with its actual ZIP path." }
$Archive = (Resolve-Path $Archive).Path
$variant = "t060"
if ($AgreementRescue) { $variant = "rescue" }
$work = Join-Path $repo ("validation-data/whitebox-v8-$variant-" + (Get-Date -Format "yyyyMMdd-HHmmss-ffff"))
New-Item -ItemType Directory -Path $work | Out-Null
function Invoke-Docker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed: $($Arguments -join ' ')" }
}
Invoke-Docker -Arguments @("image", "inspect", $Image, "--format", "{{.Id}}")
$occupied = Invoke-Docker -Arguments @("ps", "-q", "--filter", "publish=$Port")
if ($occupied) { throw "Port $Port is occupied; pass -Port with another free port." }
$name = "v8-whitebox-$variant-" + (Get-Date -Format "yyyyMMdd-HHmmss-ffff")
$arguments = @("run", "-d", "--name", $name, "--read-only", "--memory", "1g", "--cpus", "1",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "-p", "${Port}:8080",
    "-e", "DF_ENABLE_SCORE_ENDPOINT=1",
    "--mount", "type=bind,source=$repo/scripts,target=/checks,readonly",
    "--mount", "type=bind,source=$candidate,target=/candidate,readonly",
    "--mount", "type=bind,source=$Archive,target=/input/ta-samples.zip,readonly",
    "--mount", "type=bind,source=$work,target=/proof")
if ($AgreementRescue) {
    $arguments += @(
        "--mount", "type=bind,source=$repo/defender/defender/apps.py,target=/opt/defender/defender/apps.py,readonly",
        "--mount", "type=bind,source=$repo/defender/defender/reviewer_rescue.py,target=/opt/defender/defender/reviewer_rescue.py,readonly",
        "--mount", "type=bind,source=$repo/docs/evidence/phorpiex-rescue-full-pool.json,target=/rescue-proof.json,readonly")
}
$arguments += @("--entrypoint", "python", $Image, "/checks/serve_reviewer_v8_whitebox.py", "--model", "/candidate/model.json")
if ($AgreementRescue) { $arguments += @("--agreement-rescue", "--rescue-proof", "/rescue-proof.json") }
Invoke-Docker -Arguments $arguments
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
if ($AgreementRescue -and $null -eq $info.reviewer_agreement_rescue) {
    throw "The candidate did not enable the checked rescue policy."
}
$prefix = "whitebox-v8-$variant"
Invoke-Docker -Arguments @("exec", $name, "python", "/checks/score_reviewer_v8_whitebox.py",
    "--archive", "/input/ta-samples.zip", "--model", "/candidate/model.json",
    "--service-url", "http://127.0.0.1:8080", "--output-prefix", "/proof/$prefix")
$report = Get-Content -Raw (Join-Path $work "$prefix.json") | ConvertFrom-Json
$expectedMalware = 49
if ($AgreementRescue) { $expectedMalware = 50 }
if (-not $report.complete -or $report.errors -ne 0 -or
    $report.true_positives -ne $expectedMalware -or $report.true_negatives -ne 50) {
    throw "Runtime differs from cached $expectedMalware/50 malware, 50/50 benign. Inspect $work."
}
if ($AgreementRescue -and $report.agreement_rescue_count -ne 1) {
    throw "Expected exactly one rescue. Inspect $work."
}
Write-Host "PASS: actual Docker results match cached replay: $expectedMalware/50 malware, 50/50 benign."
Write-Host "Send: $(Join-Path $work "$prefix.json")"
Write-Host "Candidate remains running on port $Port; stop with: docker stop $name"
