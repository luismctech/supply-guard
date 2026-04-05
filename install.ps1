#Requires -Version 5.1
<#
.SYNOPSIS
    Install supply-guard on Windows.
.DESCRIPTION
    Downloads the latest supply-guard release, verifies its checksum,
    and installs it to a directory in your PATH.
.PARAMETER Version
    Specific version to install (e.g. "v0.3.1"). Defaults to latest.
.PARAMETER InstallDir
    Installation directory. Defaults to "$env:LOCALAPPDATA\supply-guard".
.EXAMPLE
    irm https://raw.githubusercontent.com/AlbertoMZCruz/supply-guard/main/install.ps1 | iex
.EXAMPLE
    .\install.ps1 -Version v0.3.1
#>
param(
    [string]$Version,
    [string]$InstallDir
)

$ErrorActionPreference = "Stop"
$Repo = "AlbertoMZCruz/supply-guard"
$Binary = "supply-guard.exe"

function Write-Info  { param($Msg) Write-Host "  $Msg" -ForegroundColor Blue }
function Write-Ok    { param($Msg) Write-Host "  $Msg" -ForegroundColor Green }
function Write-Err   { param($Msg) Write-Host "  Error: $Msg" -ForegroundColor Red; exit 1 }

function Get-Arch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { Write-Err "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
    }
}

function Get-LatestVersion {
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
        return $release.tag_name
    } catch {
        Write-Err "Could not fetch latest version: $_"
    }
}

$Arch = Get-Arch

if (-not $InstallDir) {
    $InstallDir = Join-Path $env:LOCALAPPDATA "supply-guard"
}

if (-not $Version) {
    Write-Info "Fetching latest version..."
    $Version = Get-LatestVersion
}

if (-not $Version) {
    Write-Err "Could not determine latest version. Use -Version to specify."
}

$VersionNum = $Version.TrimStart("v")
$Filename = "supply-guard_${VersionNum}_windows_${Arch}.zip"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$Filename"
$ChecksumUrl = "https://github.com/$Repo/releases/download/$Version/checksums.txt"

Write-Info "Downloading supply-guard $Version for windows/$Arch..."

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("supply-guard-install-" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

try {
    $ZipPath = Join-Path $TmpDir $Filename
    $ChecksumPath = Join-Path $TmpDir "checksums.txt"

    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
    Invoke-WebRequest -Uri $ChecksumUrl -OutFile $ChecksumPath -UseBasicParsing

    Write-Info "Verifying checksum..."

    $ExpectedLine = Get-Content $ChecksumPath | Where-Object { $_ -match $Filename }
    if (-not $ExpectedLine) {
        Write-Err "Could not find checksum for $Filename in checksums.txt"
    }
    $ExpectedHash = ($ExpectedLine -split "\s+")[0]

    $ActualHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLower()

    if ($ExpectedHash -ne $ActualHash) {
        Write-Err "Checksum mismatch! Expected: $ExpectedHash, Got: $ActualHash. The download may have been tampered with."
    }
    Write-Ok "Checksum verified"

    Write-Info "Extracting..."
    Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force

    $BinarySrc = Join-Path $TmpDir "supply-guard.exe"
    if (-not (Test-Path $BinarySrc)) {
        Write-Err "Binary not found in archive. Contents: $(Get-ChildItem $TmpDir -Name)"
    }

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $BinaryDest = Join-Path $InstallDir $Binary
    Move-Item -Path $BinarySrc -Destination $BinaryDest -Force

    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($currentPath -notlike "*$InstallDir*") {
        Write-Info "Adding $InstallDir to user PATH..."
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$InstallDir", "User")
        $env:Path = "$env:Path;$InstallDir"
    }

    Write-Ok "supply-guard $Version installed to $BinaryDest"
    Write-Host ""
    & $BinaryDest version

    if ($currentPath -notlike "*$InstallDir*") {
        Write-Host ""
        Write-Info "Restart your terminal for PATH changes to take effect."
    }
} finally {
    Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
