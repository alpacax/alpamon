<#
.SYNOPSIS
    Install the Alpamon agent on Windows.

.DESCRIPTION
    Downloads the latest Alpamon release, extracts alpamon.exe to a
    temporary directory, and runs `alpamon register`. The register
    command copies the binary to %ProgramFiles%\alpamon\ and creates
    a Windows Service. Intended for cloud-init, Packer, EC2 UserData,
    and Azure Custom Script Extension.

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
    Specific release tag to install (e.g., "v1.2.3"). Defaults to the
    latest release.

.EXAMPLE
    # Interactive install.
    .\install.ps1 -Url https://alpacon.example.com -Token <TOKEN>

.EXAMPLE
    # cloud-init / UserData style.
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
$versionBare = $Version.TrimStart("v")

$arch = "amd64"
$archiveName = "alpamon-$versionBare-windows-$arch.tar.gz"
$archiveUrl  = "https://github.com/alpacax/alpamon/releases/download/$Version/$archiveName"

$tempDir = Join-Path $env:TEMP ("alpamon-install-" + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

try {
    $archivePath = Join-Path $tempDir "alpamon.tar.gz"
    Write-Host "Downloading $archiveUrl ..."
    Invoke-WebRequest -Uri $archiveUrl -OutFile $archivePath -UseBasicParsing

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
