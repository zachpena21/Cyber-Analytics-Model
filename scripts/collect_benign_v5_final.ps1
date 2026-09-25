param(
    [int]$Count = 1000,
    [string]$Output = "validation-data\benign-final-4",
    [string[]]$Exclude = @(
        "validation-data\benign-modern.zip",
        "validation-data\benign-final.zip",
        "validation-data\benign-final-2.zip",
        "validation-data\benign-final-3.zip"
    )
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $repo $Output
$archive = "$destination.zip"

if ((Test-Path $destination) -or (Test-Path $archive)) {
    throw "Final output already exists at $destination or $archive; choose a new -Output name."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$seen = @{}

function Add-ExcludedHash([string]$Hash) {
    if ($Hash -match '^[0-9a-fA-F]{64}$') {
        $script:seen[$Hash.ToLowerInvariant()] = $true
    }
}

foreach ($relative in $Exclude) {
    $path = Join-Path $repo $relative
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required exclusion corpus not found: $path"
    }

    if (Test-Path -LiteralPath $path -PathType Container) {
        Get-ChildItem -LiteralPath $path -Recurse -File | ForEach-Object {
            if ($_.BaseName -match '^[0-9a-fA-F]{64}$') {
                Add-ExcludedHash $_.BaseName
            } else {
                Add-ExcludedHash (
                    (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash
                )
            }
        }
        continue
    }

    if ([IO.Path]::GetExtension($path).ToLowerInvariant() -ne ".zip") {
        throw "Exclusion must be a directory or ZIP: $path"
    }
    $zip = [IO.Compression.ZipFile]::OpenRead($path)
    try {
        foreach ($entry in $zip.Entries) {
            if ([string]::IsNullOrEmpty($entry.Name)) { continue }
            $baseName = [IO.Path]::GetFileNameWithoutExtension($entry.Name)
            if ($baseName -match '^[0-9a-fA-F]{64}$') {
                Add-ExcludedHash $baseName
                continue
            }
            $stream = $entry.Open()
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $bytes = $sha.ComputeHash($stream)
                Add-ExcludedHash (
                    ([BitConverter]::ToString($bytes)).Replace("-", "")
                )
            } finally {
                $sha.Dispose()
                $stream.Dispose()
            }
        }
    } finally {
        $zip.Dispose()
    }
}

$excludedCount = $seen.Count
if ($excludedCount -lt 3000) {
    throw "Only $excludedCount prior benign hashes were loaded; expected at least 3000."
}

New-Item -ItemType Directory -Path $destination | Out-Null
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
            Copy-Item -LiteralPath $file.FullName -Destination (
                Join-Path $destination ($hash + $file.Extension.ToLowerInvariant())
            )
            $saved++
            Write-Progress -Activity "Collecting final disjoint signed PE files" `
                -Status "$saved / $Count" -PercentComplete (($saved / $Count) * 100)
        } catch { continue }
    }
    if ($saved -ge $Count) { break }
}

Write-Progress -Activity "Collecting final disjoint signed PE files" -Completed
Compress-Archive -Path (Join-Path $destination "*") -DestinationPath $archive
Write-Host "Excluded $excludedCount prior benign hashes."
Write-Host "Saved $saved new signed PE files to $archive"
if ($saved -lt 500) {
    Write-Warning "Fewer than 500 files were collected; the final FPR estimate will be noisy."
}
