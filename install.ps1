# kosh Windows installer — https://kosh.useyukti.com
#
# Downloads the prebuilt kosh binary from GitHub Releases and installs it.
#
# Usage:
#   irm https://kosh.useyukti.com/install.ps1 | iex
#
# NOTE: Prebuilt binaries are published when a version tag (v*) is pushed to
# GitHub. If no release exists yet, this script exits with a clear error.
# In that case, install via Cargo:
#   cargo install kosh

$ErrorActionPreference = "Stop"

$Repo      = "VaarunSinha/kosh"
$Binary    = "kosh.exe"
$InstallDir = "$env:USERPROFILE\.kosh\bin"

function Write-Step   { param($m) Write-Host "  $m" }
function Write-Bold   { param($m) Write-Host $m -ForegroundColor White }
function Write-Good   { param($m) Write-Host $m -ForegroundColor Green }
function Write-Warn   { param($m) Write-Host $m -ForegroundColor Yellow }
function Fail         { param($m) Write-Host "error: $m" -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------------------
# Detect architecture
# ---------------------------------------------------------------------------
$IsArm = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq [System.Runtime.InteropServices.Architecture]::Arm64
$Arch  = if ($IsArm) { "aarch64" } else { "x86_64" }

if (-not [System.Environment]::Is64BitOperatingSystem) {
    Fail "32-bit Windows is not supported. Use 'cargo install kosh' instead."
}

$Target  = "$Arch-pc-windows-msvc"
$Archive = "kosh-$Target.zip"
$Url     = "https://github.com/$Repo/releases/latest/download/$Archive"

Write-Bold "kosh installer"
Write-Step "Platform : Windows / $Arch"
Write-Step "Asset    : $Archive"
Write-Step "URL      : $Url"
Write-Host ""

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------
$TmpDir      = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
$ArchivePath = Join-Path $TmpDir $Archive
New-Item -ItemType Directory -Path $TmpDir | Out-Null

try {
    try {
        Invoke-WebRequest -Uri $Url -OutFile $ArchivePath -UseBasicParsing
    } catch {
        Fail "Download failed — no release published yet? Try: cargo install kosh`n  $_"
    }

    # -------------------------------------------------------------------------
    # Verify checksum
    # -------------------------------------------------------------------------
    $ChecksumUrl  = "$Url.sha256"
    $ChecksumPath = "$ArchivePath.sha256"
    try {
        Invoke-WebRequest -Uri $ChecksumUrl -OutFile $ChecksumPath -UseBasicParsing
    } catch {
        Fail "Checksum file download failed: $_"
    }
    $Expected = (Get-Content $ChecksumPath -Raw).Trim().ToLower()
    $Actual   = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLower()
    if ($Expected -ne $Actual) {
        Fail "Checksum mismatch — download may be corrupted or tampered.`n  Expected: $Expected`n  Got:      $Actual"
    }

    # -------------------------------------------------------------------------
    # Extract
    # -------------------------------------------------------------------------
    Expand-Archive -Path $ArchivePath -DestinationPath $TmpDir -Force

    $Found = Get-ChildItem -Path $TmpDir -Filter $Binary -Recurse | Select-Object -First 1
    if (-not $Found) {
        Fail "Binary not found in archive."
    }

    # -------------------------------------------------------------------------
    # Install
    # -------------------------------------------------------------------------
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path $Found.FullName -Destination (Join-Path $InstallDir $Binary) -Force

    # Add InstallDir to user PATH if not already present
    $UserPath = [System.Environment]::GetEnvironmentVariable("PATH", "User") ?? ""
    if ($UserPath -notlike "*$InstallDir*") {
        [System.Environment]::SetEnvironmentVariable("PATH", "$UserPath;$InstallDir", "User")
        $env:PATH += ";$InstallDir"
        Write-Step "Added $InstallDir to your PATH."
    }

    # -------------------------------------------------------------------------
    # Verify
    # -------------------------------------------------------------------------
    $ExePath = Join-Path $InstallDir $Binary
    $Version = & $ExePath --version 2>&1

    Write-Host ""
    Write-Good "kosh installed successfully!"
    Write-Step "Version  : $Version"
    Write-Step "Location : $ExePath"
    Write-Host ""
    Write-Step "Run 'kosh init' to get started."
    Write-Step "You may need to restart your terminal for PATH changes to take effect."

} finally {
    Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
