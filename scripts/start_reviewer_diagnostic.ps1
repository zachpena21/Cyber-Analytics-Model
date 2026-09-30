<#
.SYNOPSIS
Start a frozen reviewer diagnostic container with every sample routed.
.EXAMPLE
powershell -ExecutionPolicy Bypass -File scripts\start_reviewer_diagnostic.ps1 -Version v6.1
.NOTES
Original model artifacts are preserved. Every running Docker container bound
to the requested host port is stopped. Run scoring separately from the VM.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("v5", "v6.1", "v7")]
    [string]$Version,
    [ValidateRange(1, 65535)]
    [int]$Port = 8082,
    [string]$Image = "blackbox-defense:v14-main-v7",
    [string]$PythonExecutable = "python"
)

$ErrorActionPreference = "Stop"
Get-Command docker -ErrorAction Stop | Out-Null
Get-Command $PythonExecutable -ErrorAction Stop | Out-Null
$repoRoot = Split-Path -Parent $PSScriptRoot
$artifactNames = @{
    "v5" = "boundary_reviewer_v5_candidate"
    "v6.1" = "boundary_reviewer_v6_1_candidate"
    "v7" = "boundary_reviewer_v7_gbdt_candidate"
}
$sourcePath = Join-Path $repoRoot ("defender\defender\models\" + $artifactNames[$Version])
$diagnosticPath = Join-Path $repoRoot ("validation-data\reviewer-all-route-" +
    $Version.Replace(".", "-") + "-" + [guid]::NewGuid().ToString("N"))

$prepareCode = @'
import base64
import gzip
import json
from pathlib import Path
import shutil
import sys

source, destination = map(Path, sys.argv[1:3])
plain = source / "model.json"
if plain.is_file():
    model = json.loads(plain.read_text(encoding="utf-8-sig"))
else:
    parts = sorted(source.glob("model.json.gz.b64.part-*"))
    if not parts:
        raise SystemExit(f"No plain or split model found in {source}")
    for index, part in enumerate(parts):
        if part.name != f"model.json.gz.b64.part-{index:03d}":
            raise SystemExit(f"Missing or unexpected model part: {part.name}")
    encoded = b"".join(part.read_bytes() for part in parts)
    encoded = b"".join(encoded.split())
    model = json.loads(gzip.decompress(base64.b64decode(encoded, validate=True)))

if not isinstance(model, dict) or not {"route_min", "reviewer_threshold"} <= model.keys():
    raise SystemExit("Model lacks route_min or reviewer_threshold")
threshold = float(model["reviewer_threshold"])
if not 0 <= threshold <= 1:
    raise SystemExit("Invalid saved reviewer threshold")
original_route_min = model["route_min"]
model["route_min"] = 0.0
shutil.copytree(source, destination,
                ignore=shutil.ignore_patterns("model.json.gz.b64.part-*"))
(destination / "model.json").write_text(json.dumps(model, indent=2) + "\n",
                                       encoding="utf-8")
print(json.dumps({"original_route_min": original_route_min,
                  "reviewer_threshold": threshold}))
'@
$preparationJson = $prepareCode | & $PythonExecutable - $sourcePath $diagnosticPath
if ($LASTEXITCODE -ne 0) { throw "Could not prepare diagnostic copy for $Version." }
$prepared = $preparationJson | ConvertFrom-Json
Write-Host "Reviewer: $Version"
Write-Host "Diagnostic copy: $diagnosticPath"
Write-Host "Route minimum: $($prepared.original_route_min) -> 0.0"
Write-Host "Preserved threshold: $($prepared.reviewer_threshold)"

$containerName = "blackbox-reviewer-comparison"
$runningNames = @(& docker ps --format "{{.Names}}")
if ($LASTEXITCODE -ne 0) { throw "Cannot contact Docker. Start Docker Desktop first." }
$portOwners = @()
foreach ($name in $runningNames) {
    $portsJson = & docker inspect --format "{{json .NetworkSettings.Ports}}" $name
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect container $name." }
    $bindings = $portsJson | ConvertFrom-Json
    if ($null -eq $bindings) { continue }
    $usesPort = $false
    foreach ($property in $bindings.PSObject.Properties) {
        foreach ($binding in $property.Value) {
            if ($null -ne $binding -and $binding.HostPort -eq "$Port") {
                $usesPort = $true
            }
        }
    }
    if ($usesPort) { $portOwners += $name }
}
if ($containerName -in $runningNames -and $containerName -notin $portOwners) {
    throw "$containerName is running on another port; stop it explicitly first."
}
foreach ($name in $portOwners) {
    Write-Host "Stopping container bound to host port ${Port}: $name"
    & docker stop $name | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Could not stop $name." }
}
$existingNames = @(& docker ps --all --format "{{.Names}}")
if ($LASTEXITCODE -ne 0) { throw "Could not list existing Docker containers." }
if ($containerName -in $existingNames) {
    & docker rm $containerName | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Could not remove stopped diagnostic container." }
}

$dockerArguments = @("run", "--detach", "--rm", "--name", $containerName,
    "-p", "${Port}:8080", "--memory=1g", "--cpus=1",
    "-e", "DF_MODEL_THRESH=0.510001",
    "-e", "DF_ENABLE_BOUNDARY_REVIEWER=1",
    "-e", "DF_REVIEWER_DIR=/opt/reviewer-diagnostic",
    "-e", "DF_ENABLE_SCORE_ENDPOINT=1",
    "--mount", "type=bind,source=$diagnosticPath,target=/opt/reviewer-diagnostic,readonly",
    $Image)
& docker @dockerArguments | Out-Host
if ($LASTEXITCODE -ne 0) { throw "Docker launch failed." }

Write-Host "Waiting for the diagnostic service..."
$serviceModel = $null
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    try {
        $serviceModel = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/model" -TimeoutSec 2
        break
    } catch {
        Start-Sleep -Seconds 1
    }
}
if ($null -eq $serviceModel) {
    & docker logs $containerName | Out-Host
    throw "Diagnostic service did not become ready. Inspect Docker logs."
}
if (-not $serviceModel.boundary_reviewer -or -not $serviceModel.score_endpoint_enabled) {
    throw "Reviewer or diagnostic score endpoint is not enabled."
}
if ($null -eq $serviceModel.reviewer_route_min -or
    [double]$serviceModel.reviewer_route_min -ne 0.0) {
    throw "Loaded reviewer route minimum is not 0.0."
}
if ($null -eq $serviceModel.reviewer_threshold -or
    [math]::Abs([double]$serviceModel.reviewer_threshold -
               [double]$prepared.reviewer_threshold) -gt 1e-12) {
    throw "Loaded reviewer threshold does not match the saved artifact."
}
Write-Host "Ready: reviewer $Version, route_min=0.0, threshold=$($serviceModel.reviewer_threshold)"
Write-Host "Container runs in the background. You can now score data from the VM."
Write-Host "Logs: docker logs $containerName"
