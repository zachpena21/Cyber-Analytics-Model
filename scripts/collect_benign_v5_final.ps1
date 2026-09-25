param(
    [int]$Count = 1000,
    [string]$Output = "validation-data\benign-final-4",
    [string[]]$Exclude = @()
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $repo $Output
$archive = "$destination.zip"
$validationDir = Join-Path $repo "validation-data"

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

# Always discover prior benign ZIPs automatically. Explicit -Exclude values are
# added to this set rather than replacing discovery, avoiding PowerShell array
# binding surprises at the command line.
$excludePaths = New-Object System.Collections.Generic.List[string]
if (Test-Path -LiteralPath $validationDir) {
    Get-ChildItem -LiteralPath $validationDir -File -Filter "benign-*.zip" |
        Sort-Object FullName |
        ForEach-Object {
            if ($_.FullName -ne $archive) {
                $excludePaths.Add($_.FullName)
            }
        }
}

foreach ($relative in $Exclude) {
    if ([string]::IsNullOrWhiteSpace($relative)) { continue }
    $path = if ([IO.Path]::IsPathRooted($relative)) {
        $relative
    } else {
        Join-Path $repo $relative
    }
    if (-not $excludePaths.Contains($path)) {
        $excludePaths.Add($path)
    }
}

if ($excludePaths.Count -eq 0) {
    throw "No prior benign exclusion corpora were found under $validationDir."
}

Write-Host "Loading prior benign exclusion corpora:"
foreach ($path in $excludePaths) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required exclusion corpus not found: $path"
    }

    $before = $seen.Count
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
    } else {
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
    $added = $seen.Count - $before
    Write-Host "  $path : +$added unique hashes ($($seen.Count) total)"
}

$excludedCount = $seen.Count
if ($excludedCount -lt 4000) {
    throw "Only $excludedCount prior benign hashes were loaded; expected at least 4000. Verify benign-modern.zip and benign-final through benign-final-4.zip are present in validation-data."
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
