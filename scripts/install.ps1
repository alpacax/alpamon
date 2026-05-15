#requires -Version 5.1
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
# Suppress Invoke-WebRequest progress bar; on PS 5.1 the default
# rendering slows downloads by one to two orders of magnitude, which
# is painful in cloud-init / UserData runs. Save the caller's value
# so a `iwr ... | iex` invocation doesn't inherit the suppression
# after the installer exits (script-scope assignment would normally
# shield the caller, but iex runs in the caller's scope).
$previousProgressPreference = $ProgressPreference
$ProgressPreference = "SilentlyContinue"

# Pre-declared here so the outer catch/finally can reference them even
# if a throw happens before the assignment points below.
$serviceWasRunning = $false
$tempDir = $null
# SecurityProtocol is a process-wide setting, not script-scoped, so it
# would persist in a caller that invoked the installer via `iwr | iex`.
# Capture the prior value and restore it in the finally block for the
# same reason $ProgressPreference is saved and restored above.
#
# Only meaningful on Windows PowerShell 5.1, which routes
# Invoke-WebRequest / Invoke-RestMethod through ServicePointManager.
# PowerShell 7.x reimplements those cmdlets on HttpClient and ignores
# ServicePointManager.SecurityProtocol entirely, so there is nothing
# to save or restore there. Pre-initialize to $null so the finally
# block always has a defined read target even under
# Set-StrictMode -Version Latest.
$previousSecurityProtocol = $null
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Verbose "PowerShell $($PSVersionTable.PSVersion); saving previous SecurityProtocol for restore."
    $previousSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
}
else {
    Write-Verbose "PowerShell $($PSVersionTable.PSVersion); skipping SecurityProtocol save (HttpClient ignores it)."
}

try {
    if (-not $Url -or -not $Token) {
        throw "Url and Token are required (pass as parameters or set ALPAMON_URL / ALPAMON_TOKEN)."
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "install.ps1 must be run from an elevated (Administrator) PowerShell."
    }

    # Force TLS 1.2+ before any Invoke-WebRequest / Invoke-RestMethod.
    # Older Server 2019 base images default to SSL3/TLS1.0, which fails
    # the GitHub API handshake. TLS 1.3 only exists on .NET Framework 4.8+,
    # so probe for the enum value rather than referencing the literal.
    #
    # PowerShell 7.x reimplements Invoke-WebRequest / Invoke-RestMethod
    # on top of HttpClient; ServicePointManager.SecurityProtocol still
    # exists for source compatibility but has no effect on TLS
    # negotiation there. Skip the assignment on 7.x and rely on the
    # .NET 7+ HttpClient defaults (TLS 1.2 / 1.3). If OS-level TLS is
    # degraded below 1.2 on a PS 7.x host, fix it at the OS level; the
    # installer is not the right place to paper over that.
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        $tls = [Net.SecurityProtocolType]::Tls12
        if ([Enum]::IsDefined([Net.SecurityProtocolType], 'Tls13')) {
            $tls = $tls -bor [Net.SecurityProtocolType]'Tls13'
        }
        [Net.ServicePointManager]::SecurityProtocol = $tls
        Write-Verbose "Forced ServicePointManager.SecurityProtocol = $tls (Windows PowerShell 5.x path)."
    }
    else {
        Write-Verbose "Skipping ServicePointManager.SecurityProtocol assignment on PowerShell $($PSVersionTable.PSVersion); HttpClient ignores it."
    }

    # If an alpamon service already exists, stop it so `alpamon register`
    # can replace %ProgramFiles%\alpamon\alpamon.exe without hitting
    # ERROR_SHARING_VIOLATION. Track whether it was running so a failure
    # anywhere below can put it back, matching Linux/macOS where a failed
    # register leaves the existing service untouched.
    $existingService = Get-Service -Name alpamon -ErrorAction SilentlyContinue
    if ($existingService) {
        if ($existingService.Status -eq 'Running') { $serviceWasRunning = $true }
        if ($existingService.Status -eq 'Stopped') {
            Write-Host "Existing alpamon service detected (status: Stopped); leaving as-is."
        }
        else {
            Write-Host "Existing alpamon service detected (status: $($existingService.Status)). Stopping..."
            # Skip Stop-Service if the SCM is already tearing the service
            # down; the subsequent WaitForStatus will still block until the
            # transition completes.
            if ($existingService.Status -ne 'StopPending') {
                Stop-Service -Name alpamon -Force -ErrorAction Stop
            }
            # Stop-Service returns before the SCM fully releases the binary
            # handle; without the wait, the subsequent copy can still race.
            # WaitForStatus refreshes the ServiceController's state internally,
            # so reusing $existingService is safe.
            $existingService.WaitForStatus('Stopped', '00:00:30')
        }
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
    if (-not (Get-Command tar.exe -ErrorAction SilentlyContinue)) {
        throw "tar.exe not found on PATH. Windows 10 1803 / Server 2019 or newer is required."
    }
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
catch {
    # Any throw after the service was stopped leaves a previously-running
    # alpamon down; best-effort restart to match Linux/macOS semantics
    # where a failed `alpamon register` does not touch the existing
    # service. Covers failures anywhere after service stop: WaitForStatus
    # timeout, tag resolution, tempDir creation, download, extract,
    # register.
    if ($serviceWasRunning) {
        Write-Warning "Install failed; attempting to restart previously-running alpamon service."
        Start-Service -Name alpamon -ErrorAction SilentlyContinue
    }
    throw
}
finally {
    if ($tempDir -and (Test-Path $tempDir)) {
        Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    }
    # Symmetric with the save/set guards above: only restore on the
    # PowerShell version that actually changed the value. On 7.x the
    # value was never saved ($previousSecurityProtocol is $null) and
    # writing $null into a [Net.SecurityProtocolType] property is
    # confusing at best.
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        [Net.ServicePointManager]::SecurityProtocol = $previousSecurityProtocol
        Write-Verbose "Restored ServicePointManager.SecurityProtocol = $previousSecurityProtocol."
    }
    $ProgressPreference = $previousProgressPreference
}
