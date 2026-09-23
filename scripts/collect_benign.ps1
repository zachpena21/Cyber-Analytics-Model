param(
    [int]$Count = 1000,
    [string]$Output = "validation-data\benign-modern",
    [switch]$NoArchive
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $repo $Output
New-Item -ItemType Directory -Force -Path $destination | Out-Null

$roots = @(
    "$env:WINDIR\System32",
    "$env:ProgramFiles"
)
if (${env:ProgramFiles(x86)}) {
    $roots += ${env:ProgramFiles(x86)}
}

$seen = @{}
$saved = 0
foreach ($root in $roots) {
    if (-not (Test-Path $root)) { continue }
    $files = Get-ChildItem -LiteralPath $root -Recurse -File `
        -Include *.exe,*.dll,*.scr -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        if ($saved -ge $Count) { break }
        try {
            if ($file.Length -gt 16777216) { continue }
            $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
            if ($signature.Status -ne "Valid") { continue }
            $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLower()
            if ($seen.ContainsKey($hash)) { continue }
            $seen[$hash] = $true
            Copy-Item -LiteralPath $file.FullName -Destination `
                (Join-Path $destination ($hash + $file.Extension.ToLower()))
            $saved++
            Write-Progress -Activity "Collecting signed benign PE files" `
                -Status "$saved / $Count" -PercentComplete (($saved / $Count) * 100)
        } catch {
            continue
        }
    }
    if ($saved -ge $Count) { break }
}

Write-Progress -Activity "Collecting signed benign PE files" -Completed
Write-Host "Saved $saved signed, deduplicated files to $destination"
if (-not $NoArchive) {
    $archive = "$destination.zip"
    if (Test-Path $archive) { Remove-Item -LiteralPath $archive }
    Compress-Archive -Path (Join-Path $destination "*") -DestinationPath $archive
    Write-Host "Transfer archive: $archive"
}
if ($saved -lt 500) {
    Write-Warning "Fewer than 500 benign files were collected; the 1% FPR estimate will be noisy."
}
