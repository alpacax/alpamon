# Alpamon

**Alpamon** is the open-source server agent for [Alpacon](https://alpacon.io), the AI-native PAM that governs *what* humans, AI agents, and CI/CD pipelines execute on your servers.

Installed on each managed server, Alpamon establishes an outbound-only connection to the Alpacon control plane (no inbound ports, no firewall changes) and enforces server-side decisions locally: Websh terminals, file transfers, remote command execution, and sudo verification (via the optional [alpamon-pam](https://github.com/alpacax/alpamon-pam) module). Every action runs inside a scoped work session and is recorded for audit—same shape whether the actor is human, AI agent, or CI/CD pipeline.

## Supported platforms

| Platform | Minimum version | Arch |
| --- | --- | --- |
| Linux | Ubuntu 18.04+, Debian 11+, RHEL / Rocky / AlmaLinux 8+, Oracle Linux 8+, Amazon Linux 2 / 2023, Fedora (current or previous), Raspberry Pi OS (64-bit) | amd64, arm64 |
| Linux (best-effort) | openSUSE Leap 15+, SLES 15+ | amd64, arm64 |
| macOS | 11 (Big Sur) or later | amd64, arm64 (Apple Silicon) |
| Windows | Windows 10 (1803+) / Windows 11, Windows Server 2019 or later | amd64 |

**System requirements**: 128MB RAM, 150MB free disk, outbound HTTPS to your Alpacon workspace.

## Installation

All platforms share the same second step: `alpamon register` writes the config, sets up the service, and starts it. Only the first step (getting the binary onto the machine) differs.

### Linux

**Debian / Ubuntu**
```bash
curl -s https://packagecloud.io/install/repositories/alpacax/alpamon/script.deb.sh?any=true | sudo bash
sudo apt-get install alpamon
sudo alpamon register --url https://<workspace> --token <TOKEN>
```

**RHEL / Rocky / AlmaLinux / Fedora**
```bash
curl -s https://packagecloud.io/install/repositories/alpacax/alpamon/script.rpm.sh?any=true | sudo bash
sudo yum install alpamon
sudo alpamon register --url https://<workspace> --token <TOKEN>
```

**openSUSE / SLES** (best-effort) — see [**docs/opensuse.md**](docs/opensuse.md) for the sudoers prerequisite and the `yum`-only server operations that still fail here.
```bash
sudo zypper addrepo -f 'https://packagecloud.io/alpacax/alpamon/rpm_any/rpm_any/$basearch' alpamon
sudo zypper --gpg-auto-import-keys refresh && sudo zypper install alpamon
sudo alpamon register --url https://<workspace> --token <TOKEN>
```

### macOS

```bash
# Pick the right arch for your Mac: amd64 (Intel) or arm64 (Apple Silicon)
ARCH=$(uname -m | sed 's/x86_64/amd64/')
VERSION=$(curl -s https://api.github.com/repos/alpacax/alpamon/releases/latest | grep tag_name | cut -d'"' -f4)
curl -LO "https://github.com/alpacax/alpamon/releases/download/${VERSION}/alpamon-${VERSION#v}-darwin-${ARCH}.tar.gz"
tar xzf alpamon-*.tar.gz
sudo mv alpamon /usr/local/bin/
sudo alpamon register --url https://<workspace> --token <TOKEN>
```

### Windows

See [**docs/windows.md**](docs/windows.md) for the full install / upgrade / uninstall runbook, feature compatibility matrix, and troubleshooting.

Open an elevated PowerShell (Administrator), then run one of:

**Manual** — download `alpamon-X.Y.Z-windows-amd64.zip` from [Releases](https://github.com/alpacax/alpamon/releases), extract, and run:
```powershell
.\alpamon.exe register --url https://<workspace> --token <TOKEN>
```

**Automated download-then-run** — preferred for cloud-init, EC2 UserData, Packer, Azure Custom Script Extension. Keeps the installer on disk for audit and avoids executing arbitrary remote content under Administrator:
```powershell
$env:ALPAMON_URL   = "https://<workspace>"
$env:ALPAMON_TOKEN = "<TOKEN>"
$installer = Join-Path $env:TEMP 'alpamon-install.ps1'
Invoke-WebRequest -UseBasicParsing `
    -Uri 'https://raw.githubusercontent.com/alpacax/alpamon/main/scripts/install.ps1' `
    -OutFile $installer
& powershell -ExecutionPolicy Bypass -File $installer
```

The install script itself verifies the release archive's SHA-256 against the checksums file published with the release before extracting or executing anything.

A terser pipe-to-`iex` form is also supported for quick one-liners but trades auditability for brevity:
```powershell
$env:ALPAMON_URL   = "https://<workspace>"
$env:ALPAMON_TOKEN = "<TOKEN>"
iwr https://raw.githubusercontent.com/alpacax/alpamon/main/scripts/install.ps1 -UseB | iex
```

`register` copies the binary to `C:\Program Files\alpamon\`, creates the Windows Service (`StartType=Automatic (Delayed)`, Recovery Actions configured), and starts it. Re-running `register` is idempotent.

## PAM module (optional, Linux only)

The optional `alpamon-pam` package provides PAM integration for Alpacon-managed sudo authentication:
- **pam_alpamon.so**: Verifies Alpacon users during sudo authentication
- **alpacon_approval.so**: Handles sudo command approval requests

```bash
# Debian / Ubuntu
sudo apt-get install alpamon-pam
# RHEL / CentOS
sudo yum install alpamon-pam
# openSUSE / SLES
sudo zypper install alpamon-pam
```

After install, add to `/etc/pam.d/sudo`:
```
auth [user_unknown=ignore auth_err=die success=done default=bad] pam_alpamon.so
```
And to `/etc/sudo.conf`:
```
Plugin approval_plugin alpacon_approval.so
```
The alpamon service must be running with the socket at `/var/run/alpamon/auth.sock`.

## Configuration

Alpamon reads the first file it finds in this order:

- `/etc/alpamon/alpamon.conf` (Linux production)
- `/Library/Application Support/alpamon/alpamon.conf` (macOS)
- `%ProgramData%\alpamon\alpamon.conf` (Windows)
- `~/.alpamon.conf` (any platform, development)

`register` generates this file for you. Example:

```ini
[server]
url = https://<workspace>
id = <server-id>
key = <server-key>

[ssl]
verify = true
# ca_cert = /path/to/ca.crt

[logging]
debug = false
```

### Interface reporting

Alpamon reports two things about a machine's interfaces: which interfaces it has, and how much traffic each of them carries.

**The interface list is unchanged.** It reports the interfaces it has always reported, and an agent that upgrades takes nothing out of it.

**Traffic is reported for the interfaces that say something about the machine.** The kinds a running system creates one of per container or per connection carry no traffic samples: one half of a veth pair, a macvlan or ipvlan child, and a tun or tap device. They keep their place in the interface list; only their charts go away. A kind the kernel does not name is reported rather than left out, so bridges, bonds, VLANs, VXLANs, teams, VRF masters and Open vSwitch bridges all keep reporting traffic.

Name the ones to report anyway, by exact name or by glob:

```ini
[interface]
include_virtual = veth0, cali*
```

Two interfaces are never reported either way, and `include_virtual` cannot add them: loopback, and an interface with no hardware address such as a WireGuard, OpenVPN tun or PPP link, which the report has no way to identify.

A machine that has only interfaces of those kinds, such as one running inside a container, reports traffic for them rather than for nothing at all, and logs that it did so once per run.

To leave the same kinds out of the interface list as well:

```ini
[interface]
exclude_virtual_from_inventory = true
```

Off by default, and the one setting here whose safety depends on the server. Turn it on only against a server that keeps an interface it stops being told about; a server that deletes it deletes that interface's traffic history with it.

On Linux the kind of a link is read from sysfs. macOS and Windows expose none, so there traffic covers exactly the interfaces the interface list holds.

## Service management

### Linux (systemd)

```bash
sudo systemctl status alpamon
sudo systemctl restart alpamon
sudo journalctl -u alpamon -f
```

The unit sets `KillMode=process`, so restarting or stopping alpamon signals only the agent itself, not the whole control-group. Sessions it launched—Websh terminals and detached jobs such as `tmux`, `screen`, or `nohup`'d commands—keep running across a restart, the same way `sshd` leaves active login sessions alone. Reattach to them from a new session after the agent reconnects.

The unit also sets `RestartPreventExitStatus=78`. Alpamon exits with 78 (`EX_CONFIG`) when startup hits a condition a restart cannot clear, such as a Linux distribution it cannot classify. systemd then leaves the service in `failed` instead of restarting it, so `systemctl status alpamon` still shows the reason. Fix the underlying condition and start the service again.

### macOS (launchd)

```bash
sudo launchctl print system/com.alpacax.alpamon
sudo launchctl kickstart -k system/com.alpacax.alpamon
tail -f /var/log/alpamon/alpamon.log
```

### Windows Service

```powershell
sc.exe query alpamon
Restart-Service alpamon
Get-Content "$env:ProgramData\alpamon\log\alpamon.log" -Wait -Tail 50
```

## Upgrade

Alpamon supports in-place self-update: from the Alpacon console, send an upgrade command, or run `alpamon upgrade` locally. The agent downloads the release archive from GitHub, verifies its SHA-256 checksum, validates the binary header, and swaps the running binary atomically. On Windows the running `.exe` is renamed to `alpamon.exe.old` first and cleaned up on next service start.

### Pinned upgrades

When the upgrade command names a `target_version`, the agent installs exactly that release and can undo it:

- **Verification**: on hosts that replace their own binary, the checksums file must carry a detached OpenPGP signature from a key compiled into the binary, and the archive must match both the signed checksum and the digest the console pinned, before anything on disk changes. A build without the release key bundle (the `alpamon_release_keys` build tag) refuses pinned upgrades. On apt, yum and zypper hosts the release is a version-pinned package install, trusted through the repository signature; a repository without that version fails the upgrade.
- **Intent marker**: before the swap the agent keeps the outgoing binary as `alpamon.rollback` beside the live one and writes `upgrade.pending` (JSON: attempt, from and to versions, deadline, guard unit) in the data directory (`/var/lib/alpamon` on Linux and macOS).
- **Restart and health check**: under systemd the restart is a transient timer, not an in-process re-exec. The new process must reconnect to the console, report status and run the target version before the deadline (the payload's `health_grace_seconds`, 5 minutes by default); otherwise it restores the previous version and restarts into it.
- **Guard**: under systemd a second transient timer, armed before the swap and firing two minutes after the deadline, restores the previous version if the marker still names that guard, which covers a build that cannot start at all. On package hosts the deadline counts from the end of the install, and a failed install that changed the package reinstalls the previous version at once.
- **Report**: the outcome goes to `POST /api/servers/agent-upgrades/report/`.

Without systemd (macOS, Windows, containers) there is no guard and the restart uses the existing mechanism: an in-process re-exec, or on Windows the service's recovery actions. The health check and self-rollback still run.

Without a `target_version` none of this applies: the upgrade takes the unpinned path described at the start of this section, unchanged.

## Development

### Build from source

```bash
git clone https://github.com/alpacax/alpamon.git
cd alpamon
go build -o alpamon ./cmd/alpamon         # native
GOOS=windows GOARCH=amd64 go build ./cmd/alpamon   # Windows cross-compile
```

The Go toolchain the `go` directive in `go.mod` names is required. `GOPATH/bin` should be on `PATH`. The generated Ent code is gitignored, so run `go generate ./pkg/db/ent` (see below) before the first build.

### Generate Ent schema code

The `go:generate` directive in `pkg/db/ent/generate.go` runs `go tool entc`, the codegen program registered as a `tool` directive in `go.mod`, with `pkg/db/ent` as the working directory. That is what makes the generator's relative schema and target paths resolve, so always run it through `go generate` as shown below rather than calling `go tool entc` from another directory. The generator drops the unused Atlas SQL dialects from the binary; do not invoke the ent CLI directly, which regenerates the migrate package and pulls them back in.

Building the codegen tool links `ariga.io/atlas`, so it stays in `go.mod` as an indirect dependency. It never reaches the binary: `cmd/alpamon` does not import it.

```bash
go generate ./pkg/db/ent
```

### Install Atlas CLI (only for new migrations)

Atlas is only needed when modifying schemas under `pkg/db/schema/`. Production deployments execute the embedded SQL files in `pkg/db/migration/` directly.

```bash
curl -sSf https://atlasgo.sh | sh
atlas migrate diff <migration_name> \
    --dir "file://pkg/db/migration" \
    --to "ent://pkg/db/schema" \
    --dev-url "sqlite://alpamon.db?mode=memory"
```

### Tests

```bash
go test ./... -p 1        # whole suite
go test -v ./pkg/updater  # one package
```

`-p 1` is required. The SQLite store and the system resource checks both break when packages run in parallel.

<!-- This testing-conventions guidance is mirrored in CLAUDE.md, README.md and .github/copilot-instructions.md. Edit all three together. They must agree on the rules, not on the wording: the first two carry them as prose, the third as bullets that take no trailing period. -->
Assert with [testify](https://github.com/stretchr/testify): `require` when a failed check makes the rest of the test meaningless, `assert` for the checks themselves. Prefer the specific helper over a hand-rolled comparison: `require.NoError`, `assert.ErrorContains`, `assert.DirExists`. Read what a helper accepts before reaching for it, because the shorter spelling is sometimes the weaker check. `assert.NoFileExists` is the example: it treats a directory at the path, and any other `Lstat` error, as absence, so a test that must prove a path was removed asserts `os.ErrNotExist` from `os.Stat` instead. Write every new test this way. Many older tests still call `t.Errorf` and `t.Fatalf` directly; convert one while you are already editing it rather than as a separate sweep. A bare `t.Fatal` stays correct where there is no error value to assert on, such as the timeout branch of a `select`. A test that waits on a timer belongs in a `testing/synctest` bubble: inside `synctest.Test` the clock is fake and advances only once every goroutine in the bubble is blocked, so a timeout guard fires on a real block instead of on a slow runner, and a `wg.Wait` the code under test can no longer satisfy surfaces as a deadlock rather than as a package timeout. Reach for a fixed `time.Sleep` only to hold a worker so jobs overlap. A bubble does not count network, file, or process waits as blocked, so tests backed by `httptest`, a PTY, or a real socket stay on the real clock.

### Docker testing (Linux distros)

```bash
./Dockerfiles/build.sh
docker run alpamon:ubuntu-22.04

# Custom workspace
docker run \
    -e ALPACON_URL="https://<workspace>" \
    -e PLUGIN_ID="<plugin_id>" \
    -e PLUGIN_KEY="<plugin_key>" \
    alpamon:opensuse-15
```

Covered distros: Ubuntu 22.04/20.04, Debian 11, RHEL 8/9, openSUSE Leap 15. Legacy Dockerfiles for Ubuntu 18.04, Debian 10, and CentOS 7 also ship under `Dockerfiles/` for best-effort builds against EOL platforms.

### Run locally

```bash
go run ./cmd/alpamon
# or
./alpamon
```

Local config lives at `~/.alpamon.conf`; for a fresh run against a dev server:
```ini
[server]
url = http://localhost:8000
id = 7a50ea6c-2138-4d3f-9633-e50694c847c4
key = alpaca

[logging]
debug = true
```

## Further reading

- [Alpacon documentation](https://docs.alpacax.com)
- [Register a server](https://docs.alpacax.com/use/servers/register/)
- [Agent troubleshooting](https://docs.alpacax.com/reference/troubleshooting/agent-issues/)
