<#
.SYNOPSIS
    Install the Alpamon agent on Windows.

.DESCRIPTION
    Downloads the latest Alpamon release, verifies its SHA-256
    checksum against the checksums file published alongside the
    release (transport is HTTPS; signature verification is not yet
    implemented), extracts alpamon.exe, and runs `alpamon register`.
    The register command copies the binary to %ProgramFiles%\alpamon\
    and creates a Windows Service. Intended for cloud-init, Packer,
    EC2 UserData, and Azure Custom Script Extension.

    Parameters can be provided on the command line or via environment
    variables (ALPAMON_URL, ALPAMON_TOKEN, ALPAMON_NAME,
    ALPAMON_VERSION).

.PARAMETER Url
    Alpacon console URL. Required.

.PARAMETER Token
    Registration token with the servers:register scope. Required.

.PARAMETER Name
    Server name. Defaults to the machine hostname.

.PARAMETER Version
    Specific release tag to install (e.g., "v1.2.3" or "1.2.3").
    Defaults to the latest release. A leading "v" is added if missing.

.EXAMPLE
    # Interactive install.
    .\install.ps1 -Url https://alpacon.example.com -Token <TOKEN>

.EXAMPLE
    # cloud-init / UserData. Preferred form: download and run the
    # script from a file rather than piping into Invoke-Expression.
    # This keeps the installer auditable on the target machine and
    # avoids running arbitrary remote content under Administrator
    # if the delivery URL is ever tampered with.
    $env:ALPAMON_URL   = "https://alpacon.example.com"
    $env:ALPAMON_TOKEN = "<TOKEN>"
    $installer = Join-Path $env:TEMP 'alpamon-install.ps1'
    Invoke-WebRequest -UseBasicParsing `
        -Uri 'https://raw.githubusercontent.com/alpacax/alpamon/main/scripts/install.ps1' `
        -OutFile $installer
    & powershell -ExecutionPolicy Bypass -File $installer

.EXAMPLE
    # Terse form, trades auditability for brevity. The script still
    # verifies the downloaded release archive against the checksums
    # file published alongside the release.
    $env:ALPAMON_URL   = "https://alpacon.example.com"
    $env:ALPAMON_TOKEN = "<TOKEN>"
    Invoke-WebRequest -UseBasicParsing `
        https://raw.githubusercontent.com/alpacax/alpamon/main/scripts/install.ps1 `
        | Invoke-Expression
#>
[CmdletBinding()]
param(
    [string]$Url     = $env:ALPAMON_URL,
    [string]$Token   = $env:ALPAMON_TOKEN,
    [string]$Name    = $env:ALPAMON_NAME,
    [string]$Version = $env:ALPAMON_VERSION
)

$ErrorActionPreference = "Stop"

if (-not $Url -or -not $Token) {
    throw "Url and Token are required (pass as parameters or set ALPAMON_URL / ALPAMON_TOKEN)."
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "install.ps1 must be run from an elevated (Administrator) PowerShell."
}

if (-not $Version) {
    Write-Host "Resolving latest Alpamon release..."
    $latest  = Invoke-RestMethod -UseBasicParsing `
        "https://api.github.com/repos/alpacax/alpamon/releases/latest"
    $Version = $latest.tag_name
}
# Accept both "v1.2.3" and "1.2.3"; GitHub release tags use the "v"
# prefix so we need it on the download URL path.
if (-not $Version.StartsWith("v")) {
    $Version = "v$Version"
}
$versionBare = $Version.TrimStart("v")

$arch = "amd64"
$archiveName   = "alpamon-$versionBare-windows-$arch.tar.gz"
$checksumsName = "alpamon-$versionBare-checksums.sha256"
$archiveUrl    = "https://github.com/alpacax/alpamon/releases/download/$Version/$archiveName"
$checksumsUrl  = "https://github.com/alpacax/alpamon/releases/download/$Version/$checksumsName"

$tempDir = Join-Path $env:TEMP ("alpamon-install-" + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

try {
    $archivePath   = Join-Path $tempDir "alpamon.tar.gz"
    $checksumsPath = Join-Path $tempDir $checksumsName

    Write-Host "Downloading $archiveUrl ..."
    Invoke-WebRequest -Uri $archiveUrl -OutFile $archivePath -UseBasicParsing

    Write-Host "Downloading $checksumsUrl ..."
    Invoke-WebRequest -Uri $checksumsUrl -OutFile $checksumsPath -UseBasicParsing

    # Verify the archive against the checksums file published with
    # the release, before we extract and execute anything from it.
    # Transport is HTTPS; signature verification of the checksums
    # file itself is not yet implemented (see updater.go TODO). This
    # mirrors the agent's built-in self-updater.
    $expectedLine = Get-Content $checksumsPath | Where-Object {
        $parts = $_ -split '\s+', 2
        $parts.Length -eq 2 -and $parts[1].Trim() -eq $archiveName
    } | Select-Object -First 1
    if (-not $expectedLine) {
        throw "Checksum for $archiveName not found in $checksumsName."
    }
    $expectedHash = ($expectedLine -split '\s+', 2)[0].Trim()
    $actualHash   = (Get-FileHash -Algorithm SHA256 -Path $archivePath).Hash
    if ($actualHash.ToLower() -ne $expectedHash.ToLower()) {
        throw "SHA-256 mismatch for ${archiveName}: expected $expectedHash, got $actualHash."
    }
    Write-Host "Checksum verified."

    Write-Host "Extracting..."
    # tar.exe has shipped with Windows since 10 1803 / Server 2019.
    & tar.exe -xzf $archivePath -C $tempDir
    if ($LASTEXITCODE -ne 0) {
        throw "tar extraction failed (exit code $LASTEXITCODE). Windows 10 1803 / Server 2019 or newer required."
    }

    $exePath = Join-Path $tempDir "alpamon.exe"
    if (-not (Test-Path $exePath)) {
        throw "alpamon.exe not found in the extracted archive."
    }

    $registerArgs = @("register", "--url", $Url, "--token", $Token)
    if ($Name) { $registerArgs += @("--name", $Name) }

    Write-Host "Running alpamon register (installs to Program Files and starts the service)..."
    & $exePath @registerArgs
    if ($LASTEXITCODE -ne 0) {
        throw "alpamon register failed with exit code $LASTEXITCODE."
    }

    Write-Host ""
    Write-Host "Alpamon installed and registered."
}
finally {
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
}
