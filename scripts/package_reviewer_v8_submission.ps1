param([string]$Work = "", [string]$Image = "blackbox-defense:v8-final", [int]$DiagnosticPort = 8083)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $Work) {
    $passed = @(Get-ChildItem (Join-Path $repo "validation-data") -Directory -Filter "submission-v8-*" |
        Where-Object { Test-Path (Join-Path $_.FullName "submission-preflight-summary.json") } |
        Sort-Object Name -Descending)
    if (-not $passed) { throw "No completed submission preflight found" }
    $Work = $passed[0].FullName
}
$Work = (Resolve-Path $Work).Path
$preflight = Get-Content (Join-Path $Work "submission-preflight-summary.json") -Raw | ConvertFrom-Json
$imageId = & docker image inspect $Image --format "{{.Id}}"
if ($LASTEXITCODE -ne 0 -or $imageId -ne $preflight.image_id) { throw "Tested image identity differs" }
$ids = @(& docker ps -q --filter "ancestor=$Image" --filter "publish=$DiagnosticPort")
if ($LASTEXITCODE -ne 0 -or $ids.Count -ne 1) { throw "Expected one running v8 diagnostic on port $DiagnosticPort" }
$id = $ids[0]
$inspect = (& docker inspect $id | ConvertFrom-Json)[0]
if ($LASTEXITCODE -ne 0 -or $inspect.Image -ne $imageId) { throw "Diagnostic image identity differs" }
$usage = & docker exec $id python -c "import json; from pathlib import Path; s=Path('/proc/1/status').read_text(); fields={line.split(':')[0]:line.split(':',1)[1].strip() for line in s.splitlines() if line.startswith(('VmRSS:','VmHWM:'))}; paths=[Path('/sys/fs/cgroup/memory.peak'),Path('/sys/fs/cgroup/memory/memory.max_usage_in_bytes')]; p=next((p for p in paths if p.is_file()),None); print(json.dumps(dict(process=fields,cgroup_peak_bytes=int(p.read_text()) if p else None)))"
if ($LASTEXITCODE -ne 0) { throw "Resource measurement failed" }
$resources = $usage | ConvertFrom-Json
$resources | Add-Member -NotePropertyName image_id -NotePropertyValue $imageId
$resources | Add-Member -NotePropertyName oom_killed -NotePropertyValue $inspect.State.OOMKilled
$resources | Add-Member -NotePropertyName memory_limit_bytes -NotePropertyValue $inspect.HostConfig.Memory
$resources | Add-Member -NotePropertyName nano_cpus -NotePropertyValue $inspect.HostConfig.NanoCpus
$resources | Add-Member -NotePropertyName readonly -NotePropertyValue $inspect.HostConfig.ReadonlyRootfs
$resources | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 (Join-Path $Work "submission-resource-summary.json")
& docker run --rm --network none --read-only -e PYTHONDONTWRITEBYTECODE=1 -v "${repo}:/repo:ro" -v "${Work}:/work" --entrypoint python $Image /repo/scripts/package_reviewer_v8_submission.py --repo /repo --work /work
if ($LASTEXITCODE -ne 0) { throw "Submission packaging failed; see output above" }
Write-Host "ZIP and submission-package-summary.json saved in $Work"
Write-Host "Base-image course requirements still need review before submission. No upload has been performed."
