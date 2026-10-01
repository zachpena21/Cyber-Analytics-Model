[CmdletBinding()]
param(
    [string[]]$Roots = @("$env:WINDIR\System32\drivers", "$env:WINDIR\System32\DriverStore\FileRepository", "$env:ProgramFiles", "${env:ProgramFiles(x86)}"),
    [string]$SourceId = "zach-windows-coverage-dev",
    [ValidateSet("development", "evaluation")][string]$Role = "development",
    [string]$Output = "validation-data\benign-v8-coverage.zip",
    [int]$MaxFiles = 5000,
    [long]$MaxTotalBytes = 1073741824,
    [int]$MaxFileBytes = 16777216
)
$ErrorActionPreference = "Stop"
if ($MaxFiles -lt 1 -or $MaxTotalBytes -lt 1 -or $MaxFileBytes -lt 1) { throw "Collection limits must be positive." }
if (Test-Path -LiteralPath $Output) { throw "Output exists; choose a new -Output path." }
$archivePath = [System.IO.Path]::GetFullPath($Output)
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($archivePath)) | Out-Null
$tempPath = $archivePath + ".tmp-" + [guid]::NewGuid().ToString("N")
$extensions = @(".exe", ".dll", ".sys", ".ocx", ".cpl", ".pyd")
$random = [System.Random]::new(704)
$files = @()
$enumerationErrors = @()
foreach ($root in $Roots) {
    if (-not $root -or -not (Test-Path -LiteralPath $root -PathType Container)) { continue }
    $issues = @()
    $files += @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue -ErrorVariable issues |
        Where-Object { $extensions -contains $_.Extension.ToLowerInvariant() -and $_.Length -le $MaxFileBytes -and -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) } |
        ForEach-Object { [pscustomobject]@{ Path = $_.FullName; Shuffle = $random.NextDouble() } })
    $enumerationErrors += @($issues | ForEach-Object { $_.Exception.Message })
}
$files = @($files | Sort-Object Shuffle, Path)
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$seen = [System.Collections.Generic.HashSet[string]]::new()
$records = [System.Collections.Generic.List[object]]::new()
$readErrors = [System.Collections.Generic.List[object]]::new()
$hash = [System.Security.Cryptography.SHA256]::Create()
$total = [long]0
$zip = $null
try {
    $zip = [System.IO.Compression.ZipFile]::Open($tempPath, [System.IO.Compression.ZipArchiveMode]::Create)
    foreach ($item in $files) {
        if ($records.Count -ge $MaxFiles) { break }
        try {
            $bytes = [System.IO.File]::ReadAllBytes($item.Path)
            if ($bytes.Length -lt 2 -or $bytes.Length -gt $MaxFileBytes -or $bytes[0] -ne 77 -or $bytes[1] -ne 90) { continue }
            if ($total + $bytes.Length -gt $MaxTotalBytes) { continue }
            $sha = ([System.BitConverter]::ToString($hash.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
            if ($seen.Contains($sha)) { continue }
            $entryName = "samples/" + $sha + [System.IO.Path]::GetExtension($item.Path).ToLowerInvariant()
            $entry = $zip.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
            $stream = $entry.Open()
            try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
            $seen.Add($sha) | Out-Null
            $records.Add([pscustomobject]@{ sha256 = $sha; archive_member = $entryName; original_path = $item.Path; byte_size = $bytes.Length; label = 0; source_id = $SourceId; role = $Role })
            $total += $bytes.Length
            if ($records.Count % 100 -eq 0) { Write-Host "Collected $($records.Count) unique benign-source PE candidates" }
        } catch { $readErrors.Add([pscustomobject]@{ path = $item.Path; error = $_.Exception.Message }) }
    }
    if ($records.Count -eq 0) { throw "No readable MZ files found in the selected roots." }
    $manifest = [ordered]@{ source_id = $SourceId; role = $Role; label_basis = "User-selected trusted installed-software/Windows roots; no signature-based label inference"; roots = $Roots; sample_count = $records.Count; total_bytes = $total; collection_limits = @{ max_files = $MaxFiles; max_file_bytes = $MaxFileBytes; max_total_bytes = $MaxTotalBytes }; enumeration_errors = $enumerationErrors; read_errors = @($readErrors.ToArray()); samples = @($records.ToArray()) }
    $entry = $zip.CreateEntry("collection-manifest.json")
    $writer = [System.IO.StreamWriter]::new($entry.Open(), [System.Text.UTF8Encoding]::new($false))
    try { $writer.Write(($manifest | ConvertTo-Json -Depth 8)) } finally { $writer.Dispose() }
    $zip.Dispose(); $zip = $null
    [System.IO.File]::Move($tempPath, $archivePath)
    Write-Host "Saved $($records.Count) unique files to $archivePath"
    Write-Host "Copy this ZIP into the VM's validation-data folder, then run reviewer_v8_coverage.py."
} finally {
    if ($zip) { $zip.Dispose() }
    $hash.Dispose()
    if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath }
}
