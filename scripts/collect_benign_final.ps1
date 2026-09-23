param(
    [int]$Count = 1000,
    [string]$Output = "validation-data\benign-final",
    [string]$Exclude = "validation-data\benign-modern"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $repo $Output
$excludedDirectory = Join-Path $repo $Exclude
New-Item -ItemType Directory -Force -Path $destination | Out-Null

$seen = @{}
if (Test-Path $excludedDirectory) {
    Get-ChildItem -LiteralPath $excludedDirectory -File -ErrorAction SilentlyContinue |
        ForEach-Object {
            if ($_.BaseName -match '^[0-9a-fA-F]{64}$') {
                $seen[$_.BaseName.ToLowerInvariant()] = $true
            } else {
                try {
                    $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
                    $seen[$digest] = $true
                } catch {}
            }
        }
}
$excludedCount = $seen.Count

$roots = @("$env:WINDIR\System32", "$env:ProgramFiles")
if (${env:ProgramFiles(x86)}) { $roots += ${env:ProgramFiles(x86)} }

$saved = 0
foreach ($root in $roots) {
    if (-not (Test-Path $root)) { continue }
    $files = Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        if ($saved -ge $Count) { break }
        try {
            if ($file.Extension.ToLowerInvariant() -notin @('.exe', '.dll', '.scr')) { continue }
            if ($file.Length -gt 16777216) { continue }
            $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
            if ($signature.Status -ne "Valid") { continue }
            $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
            if ($seen.ContainsKey($hash)) { continue }
            $seen[$hash] = $true
            Copy-Item -LiteralPath $file.FullName -Destination `
                (Join-Path $destination ($hash + $file.Extension.ToLowerInvariant()))
            $saved++
            Write-Progress -Activity "Collecting disjoint signed benign PE files" `
                -Status "$saved / $Count" -PercentComplete (($saved / $Count) * 100)
        } catch { continue }
    }
    if ($saved -ge $Count) { break }
}

Write-Progress -Activity "Collecting disjoint signed benign PE files" -Completed
$archive = "$destination.zip"
if (Test-Path $archive) { Remove-Item -LiteralPath $archive }
Compress-Archive -Path (Join-Path $destination "*") -DestinationPath $archive
Write-Host "Excluded $excludedCount prior hashes."
Write-Host "Saved $saved new signed PE files to $archive"
if ($saved -lt 500) {
    Write-Warning "Fewer than 500 files were collected; the final FPR estimate will be noisy."
}
