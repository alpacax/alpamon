# Alpamon on Windows

This document is the canonical runbook for installing, upgrading, and
uninstalling the Alpamon agent on Windows, plus the feature
compatibility matrix versus Linux.

For Linux/macOS installation paths, see the [project README](../README.md).

## Prerequisites

- **Windows Server 2019 or later** (Server 2022 / 2025), or **Windows 10
  1803+ / Windows 11** on desktop SKUs. Windows Server 2016 and older
  are not supported; the built-in `tar.exe` and modern PowerShell
  features the installer relies on are not present there.
- **amd64 (x64)** architecture. ARM64 Windows is not built today; see
  [tracking in the release matrix](#unsupported-on-windows).
- **Administrator PowerShell.** Service registration, file placement
  under `%ProgramFiles%`, and the `alpamon.exe register` flow all
  require elevation. Non-admin sessions fail with a clear elevation
  hint, but they fail—do not try to work around it by running from
  a user-writable directory.
- **Outbound HTTPS** to:
  - your Alpacon workspace URL
  - `github.com` and `objects.githubusercontent.com` (for
    `install.ps1` downloads and self-update checks)
- **150 MB free disk**, **128 MB RAM** minimum.

## Install

Windows releases publish both a versioned `.tar.gz` archive and a
`.zip` archive, both signed on transport (Authenticode signing of the
binary itself is tracked as a follow-up; see [unsupported
features](#unsupported-on-windows)). The `.tar.gz` artifact is what
`install.ps1` and the in-agent self-updater consume; the `.zip`
artifact supports manual extract workflows and the stable-alias
download described below. There are two supported install paths.

### Option A: `install.ps1` (recommended)

`scripts/install.ps1` is designed for cloud-init, EC2 UserData, Packer,
and Azure Custom Script Extension. It verifies the SHA-256 of the
downloaded archive against the release checksums file before extracting
or executing anything.

```powershell
# Elevated PowerShell (Run as Administrator)
$env:ALPAMON_URL   = "https://<workspace>"
$env:ALPAMON_TOKEN = "<TOKEN>"
$installer = Join-Path $env:TEMP 'alpamon-install.ps1'
Invoke-WebRequest -UseBasicParsing `
    -Uri 'https://raw.githubusercontent.com/alpacax/alpamon/main/scripts/install.ps1' `
    -OutFile $installer
& powershell -ExecutionPolicy Bypass -File $installer
```

The installer will:

1. Resolve the latest release tag (or use `$env:ALPAMON_VERSION` if
   you pin one).
2. Download the `alpamon-<version>-windows-amd64.tar.gz` archive and
   the sibling `alpamon-<version>-checksums.sha256`.
3. Verify the archive SHA-256 against the checksums file; fail hard if
   they disagree.
4. Extract into a scratch directory in `$env:TEMP`.
5. Invoke `alpamon.exe register --url <workspace> --token <token>`,
   which copies the binary into `%ProgramFiles%\alpamon\alpamon.exe`
   and starts the service.
6. Delete the scratch directory on success *or* failure.

#### Re-running `install.ps1`

`install.ps1` is safe to re-run on a host that already has the
`alpamon` service installed. If the service exists, the script stops
it (and waits for the SCM to release the binary handle) before
touching `%ProgramFiles%\alpamon\alpamon.exe`, so you will not see the
`ERROR_SHARING_VIOLATION` that a naive re-run would otherwise hit.

Re-running on an **already-registered** host still fails at the
`alpamon register` step, because `register` refuses to run when
`%ProgramData%\alpamon\alpamon.conf` already exists—this matches the
Linux and macOS behavior and prevents a silent re-registration. To
upgrade an already-registered host, use `alpamon upgrade` or the
[Manual fallback](#manual-fallback) recipe below.

If the install fails after the service was stopped, the script
best-effort restarts the previously-running service before exiting
non-zero, so a transient network or checksum failure does not leave
the host with a downed agent. On Windows PowerShell 5.1 the script
forces TLS 1.2+ at the .NET `ServicePointManager` level, so stock
Server 2019 images do not need a manual TLS shim. On PowerShell 7.x
the installer relies on the .NET HttpClient defaults instead—see
[PowerShell compatibility](#powershell-compatibility) for the full
matrix.

A terser pipe-to-`iex` form is also supported; it still performs the
checksum verification inside the script, but trades local-audit
friendliness for brevity:

```powershell
$env:ALPAMON_URL   = "https://<workspace>"
$env:ALPAMON_TOKEN = "<TOKEN>"
iwr https://raw.githubusercontent.com/alpacax/alpamon/main/scripts/install.ps1 -UseB | iex
```

### PowerShell compatibility

`install.ps1` is verified against both Windows PowerShell 5.1
(`powershell.exe`, the in-box shell on Windows Server 2019/2022 and
Windows 10/11) and PowerShell 7.x (`pwsh.exe`, the cross-platform
build shipped via the Microsoft Store and `winget`).

| Shell | Invocation | TLS path |
|---|---|---|
| Windows PowerShell 5.1 | `powershell -ExecutionPolicy Bypass -File install.ps1` | `Invoke-WebRequest` routes through `[Net.ServicePointManager]`; the script forces TLS 1.2 (and TLS 1.3 when the `Tls13` enum is present, which requires .NET Framework 4.8+) before any network call |
| PowerShell 7.x | `pwsh -File install.ps1` | `Invoke-WebRequest` is reimplemented on `HttpClient`, which ignores `ServicePointManager.SecurityProtocol`; the script relies on the HttpClient/OS defaults (TLS 1.2, plus TLS 1.3 when the runtime and SChannel/OpenSSL support it—on Windows that means Server 2022 / Windows 11 or newer) |

The version check uses `$PSVersionTable.PSEdition -eq 'Desktop'` so
only Windows PowerShell (the `Desktop` edition built on .NET
Framework) takes the legacy `ServicePointManager` TLS path.
PowerShell 6.x and 7.x both report `Core` edition and use the
HttpClient-based web cmdlets, so they fall through to the HttpClient
defaults; treating either as 5.1 would emit a misleading verbose
message and a TLS assignment the HTTP stack ignores. PowerShell 4.x
and earlier are rejected by a `#requires -Version 5.1` directive at
the top of the script, which fails fast with a clear error instead
of producing a confusing mid-run cmdlet failure.

If a host running PowerShell 7.x has OS-level TLS configured below 1.2
(very old Windows 10 baselines with disabled TLS 1.2, custom Group
Policy lockdowns), `install.ps1` cannot work around it—the HttpClient
is bound by `SChannel`. Re-enable TLS 1.2 at the OS level before
running the installer; the same fix applies to every other HTTPS
client on that host.

Pass `-Verbose` to either shell to see which TLS path the installer
selected:

```powershell
& pwsh -File .\install.ps1 -Verbose
```

### Option B: manual extract + `alpamon register`

```powershell
# Elevated PowerShell (Run as Administrator)
$version = "X.Y.Z"  # tag without leading "v"

Invoke-WebRequest -UseBasicParsing `
  -Uri "https://github.com/alpacax/alpamon/releases/download/v$version/alpamon-$version-windows-amd64.zip" `
  -OutFile "$env:TEMP\alpamon.zip"

Expand-Archive -Path "$env:TEMP\alpamon.zip" -DestinationPath "$env:TEMP\alpamon-install" -Force

& "$env:TEMP\alpamon-install\alpamon.exe" register `
    --url "https://<workspace>" --token "<TOKEN>"
```

`register` refuses to run on an already-registered host: if
`%ProgramData%\alpamon\alpamon.conf` exists it exits non-zero rather
than silently re-provisioning. This matches the Linux and macOS
behavior. To upgrade an already-registered host use `alpamon upgrade`
(or the [Manual fallback](#manual-fallback) recipe below); to
re-register from scratch, first [Uninstall](#uninstall) and then run
Option A or Option B.

> The zip can be extracted anywhere—`alpamon.exe register` copies
> itself into `%ProgramFiles%\alpamon\alpamon.exe` and re-executes from
> there, so the Windows Service Manager entry always points at a
> stable install path.

#### Stable-name download URL

For provisioning flows that don't want to pin to a specific version
(image build pipelines, Ansible roles, `alpacon-server` registration
templates), every release also attaches an unversioned
`alpamon-windows-amd64.zip`:

```powershell
$stableUrl = "https://github.com/alpacax/alpamon/releases/latest/download/alpamon-windows-amd64.zip"
Invoke-WebRequest -UseBasicParsing -Uri $stableUrl -OutFile "$env:TEMP\alpamon.zip"
```

The bytes are identical to the versioned archive (same SHA-256 in the
published checksums file), so audit trails are preserved: compute the
hash of the downloaded alias and look for a matching
`alpamon-<ver>-windows-amd64.zip` line in the release's
`alpamon-<ver>-checksums.sha256`.

Notes:

- This alias is available from **alpamon v2.1.3 onward**. For older
  tags, only the versioned archive is published.
- `install.ps1` and the in-agent self-updater intentionally continue
  to resolve a specific tag and download the versioned `.tar.gz`
  (`pkg/updater/updater.go` hardcodes the `.tar.gz` suffix and
  requires an exact version to record), so they are unaffected by the
  alias.

## Paths

| Role | Location | Created by |
|---|---|---|
| Binary | `%ProgramFiles%\alpamon\alpamon.exe` | `alpamon register` (self-copy from the extract location) |
| Configuration | `%ProgramData%\alpamon\alpamon.conf` | `alpamon register` |
| Logs | `%ProgramData%\alpamon\log\alpamon.log` | agent runtime |
| Runtime state | `%ProgramData%\alpamon\run\` | agent runtime |
| Local metrics DB | `%ProgramData%\alpamon\data\` | agent runtime |
| Staged new binary (during upgrade) | `%ProgramFiles%\alpamon\alpamon.exe.new` | self-updater (renamed into place atomically) |
| Previous binary (pending deletion) | `%ProgramFiles%\alpamon\alpamon.exe.old` | self-updater (cleaned up on next start, or scheduled for reboot-time removal) |

`%ProgramFiles%` and `%ProgramData%` are read from the process
environment at runtime, so the agent tolerates non-default locations
(custom drive, localized install). When `%ProgramData%` is unset
(unusual but defensive), the agent falls back to `C:\ProgramData`.

## Service management

Alpamon runs as a Windows Service named `alpamon`, display name
`"Alpamon Agent"`, start type `Automatic (Delayed Start)`, with
recovery actions set to restart twice with a 5-second delay before
giving up. All commands below require elevated PowerShell.

```powershell
# Status
Get-Service alpamon
sc.exe query alpamon          # verbose form with last exit code

# Start / stop / restart
Start-Service alpamon
Stop-Service  alpamon
Restart-Service alpamon

# Follow the log
Get-Content "$env:ProgramData\alpamon\log\alpamon.log" -Wait -Tail 50
```

The service starts as `LocalSystem`; see [Permissions and
identity](#permissions-and-identity) for what that means for commands
sent from Alpacon.

### Permissions and identity

Alpamon cannot yet demote privileges on Windows (see [unsupported
features](#unsupported-on-windows)), so every command from the Alpacon
console executes with SYSTEM rights regardless of the requesting user.
In practice:

- **Websh works for any enabled local user**, and for `Administrator`
  even when the built-in account is OS-level disabled (the Windows
  10 / 11 default). Granting Websh to `alice` does not run commands
  as `alice`—they run as SYSTEM with `alice` as the audit label.
- **Commands run with full SYSTEM privileges**, irrespective of the
  session's displayed user. Treat any Websh-enabled local user as
  effectively SYSTEM on this host, and configure Alpacon roles and
  policies accordingly. The displayed user is not a permission
  boundary; **Alpacon RBAC is**.
- **The roster of Websh-eligible users is part of the security
  posture.** A local administrator on the host can re-enable an
  otherwise-disabled local account (such as `Guest` or
  `WDAGUtilityAccount`) and turn it into a Websh persistence
  channel. Alarm on unexpected new `login_enabled` users in the
  Alpacon audit feed.
- **`whoami` inside the session prints `nt authority\system`**, not
  the requested user. This is the current expected behavior; it will
  change when credential-based privilege demotion ships
  (`CreateProcessAsUser` with a logon token). Until then, attributing
  a SYSTEM-level action to a specific operator requires correlating
  the Alpacon console audit log (Alpacon user → target local user)
  with the host's Windows event log (SYSTEM-level execution trace);
  neither alone is sufficient.

**WebFTP file access scope.** Because every command runs as SYSTEM
(above), WebFTP can read and write any path the SYSTEM account has
access to—including system directories like `C:\Windows\System32`, the
alpamon log directory under `%ProgramData%\alpamon\`, and any user
profile on the host. There is no agent-side containment to the
requesting operator's home directory; until credential-based privilege
demotion ships, access scoping is the responsibility of **Alpacon
RBAC** and the **roster of Websh-eligible users**, not the agent.
Operators should treat WebFTP on Windows as "SYSTEM-level filesystem
access labeled with the operator's identity for audit", in the same way
Websh is treated today.

## Upgrade

The agent ships with a self-updater that handles the normal case:

- **From the Alpacon console**: issue an `upgrade` command. The
  agent downloads the latest release archive from GitHub, verifies the
  SHA-256 checksum, swaps the running binary, and restarts itself
  under the Service Control Manager.
- **Local CLI**: running `alpamon upgrade` (or re-running
  `install.ps1` with a newer `$env:ALPAMON_VERSION`) triggers the same
  flow.

Because Windows holds the running `.exe` locked, the updater renames
the current binary to `alpamon.exe.old` via `MoveFileEx`, writes the
new binary, and then schedules the `.old` file for deletion on the
next service start. If you see an `alpamon.exe.old` after an upgrade,
leave it—the next service start cleans it up automatically.

### Manual fallback

If the self-update path fails (for example, outbound access to
`github.com` is blocked at upgrade time):

```powershell
Stop-Service alpamon

# Download + verify the new archive as in "Option B" above.
# Then overwrite the installed binary in place:
Copy-Item -Force "$env:TEMP\alpamon-install\alpamon.exe" `
    "$env:ProgramFiles\alpamon\alpamon.exe"

Start-Service alpamon
Get-Content "$env:ProgramData\alpamon\log\alpamon.log" -Wait -Tail 50
```

Do **not** use `alpamon register` to perform an upgrade on an
already-registered machine—it refuses to run when a configuration
file already exists, to avoid silently clobbering an existing
registration.

## Uninstall

There is no dedicated uninstaller; the footprint is small and cleanup
is three commands. Run from elevated PowerShell:

```powershell
Stop-Service alpamon -ErrorAction SilentlyContinue
sc.exe delete alpamon

Remove-Item -Recurse -Force "$env:ProgramFiles\alpamon"  -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$env:ProgramData\alpamon"   -ErrorAction SilentlyContinue
```

Order matters: stop the service and unregister it from the SCM *before*
deleting the binary. Otherwise `Remove-Item` will fail with a sharing
violation because `alpamon.exe` is held open by the still-running
service.

After the uninstall, the server still exists on the Alpacon side.
Delete it from the Alpacon console separately if you do not plan to
re-register.

## Feature compatibility

Alpamon on Windows targets the same day-to-day operator workflows as
Linux: remote shell, file transfer, system metrics, and the
browser-based Websh terminal. Features that depend on Unix-specific
kernels, configuration files, or privilege models are not yet
implemented.

### Supported on Windows

| Capability | Implementation notes |
|---|---|
| Remote shell (`exec`, `shell`) | `powershell.exe -NoLogo -Command`; supports `&&`, `\|\|`, `;` operators |
| Websh (browser terminal) | ConPTY / Microsoft Pseudoconsole—see `pkg/runner/pty_windows.go` |
| File upload / download | Direct `ReadFile` / `WriteFile`, parent directories auto-created. Runs as SYSTEM; see [Permissions and identity](#permissions-and-identity) |
| System info (commit / sync) | Via `gopsutil`; users enumerated via `Get-LocalUser`, groups via `Get-LocalGroup` |
| System control | `restart`, `reboot`, `shutdown`, `upgrade`, `quit` |
| Realtime metrics | CPU, memory, disk, network (gopsutil) |
| Self-update | `MoveFileEx` for locked-binary replace; reboot-time cleanup of `.old` |
| Service lifecycle | Windows SCM integration with Stop / Shutdown / recovery actions |

### Unsupported on Windows

| Capability | Status |
|---|---|
| User management (`adduser` / `deluser` / `moduser`) | Intentionally not registered in `factory_windows.go`—server enforces via `NO_ADDUSER_PLATFORMS` |
| Group management (`addgroup` / `delgroup`) | Same as above |
| Windows Firewall integration | Not implemented; Linux `nftables` / `iptables` handler has no Windows equivalent today |
| Tunnel (reverse-proxy) | `pkg/runner/tunnel_windows.go` returns an explicit error |
| Code-Server integration | Returns an explicit error on Windows |
| Privilege demotion (run-as user) | Stub: all commands execute as `LocalSystem`. No `setuid` equivalent; full fix requires `CreateProcessAsUser` |
| TTY resize via `SIGWINCH` | ConPTY has no Unix signal equivalent; the resize event is still forwarded over the wire, so terminals resize correctly |
| Authenticode signing of `alpamon.exe` | Not yet signed; SmartScreen may warn on first run. Transport-layer integrity is provided by the checksums file |
| ARM64 Windows builds | Not built today; tracking as a separate issue |
| PAM integration (`alpamon-pam` package) | Linux-only by construction (relies on PAM) |

Operators targeting Windows should not rely on the unsupported
features listed above. Commands hitting an unsupported handler surface
an explicit error in the Alpacon console rather than silently
succeeding.

## Logs

Alpamon writes to a single log file:

- **Path:** `%ProgramData%\alpamon\log\alpamon.log`
- **Retention:** no automatic rotation today. On long-running
  Windows servers the file will grow unbounded; operators who need
  rotation should configure it externally (for example with a
  scheduled task that archives and truncates on a size threshold) or
  track this limitation for the log-rotation work item.

To tail the log live:

```powershell
Get-Content "$env:ProgramData\alpamon\log\alpamon.log" -Wait -Tail 50
```

The Windows Event Log is **not** currently a sink—failures that
happen before the log file is open (for example, missing config file)
are reported to stdout and, under SCM, mirrored to the service
recovery log.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `install.ps1 must be run from an elevated (Administrator) PowerShell` | Non-elevated session | Right-click PowerShell → Run as Administrator |
| `failed to create install directory: access is denied` during `register` | Non-elevated session (same root cause) | As above |
| `failed to create destination ... the process cannot access the file because it is being used by another process` | Existing `alpamon` service still holds the binary open (only seen when running `alpamon register` directly, not via `install.ps1`) | `Stop-Service alpamon` before rerunning, or use `install.ps1` which stops the service automatically |
| `Install failed; attempting to restart previously-running alpamon service` (warning from `install.ps1`) | Download, checksum, extract, or `register` failed after the service was stopped | Read the preceding error for the root cause; the previously-running service is restarted on a best-effort basis, so the host is back in its prior state |
| `connect to service manager: access is denied` | Non-elevated session, or Group Policy blocking SCM access | Elevate; if policy-blocked, contact your domain admin |
| Service enters `StartPending` and never reaches `Running` | Bad config file, missing network, or dispatcher panic at startup | Inspect `%ProgramData%\alpamon\log\alpamon.log`; the crash reason is logged before SCM times the service out |
| `alpamon.exe.old` lingering after upgrade | Normal: deletion is scheduled for next service start | `Restart-Service alpamon` to force the cleanup |
| SmartScreen blocks the downloaded binary | No Authenticode signature on the archive yet | Unblock the specific file via `Unblock-File`, or use `install.ps1` which triggers the run outside of the zone-taint flow |
