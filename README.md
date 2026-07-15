# Alpamon

**Alpamon** is the open-source server agent for [Alpacon](https://alpacon.io), the AI-native PAM that governs *what* humans, AI agents, and CI/CD pipelines execute on your servers.

Installed on each managed server, Alpamon establishes an outbound-only connection to the Alpacon control plane (no inbound ports, no firewall changes) and enforces server-side decisions locally: Websh terminals, file transfers, remote command execution, and sudo verification (via the optional [alpamon-pam](https://github.com/alpacax/alpamon-pam) module). Every action runs inside a scoped work session and is recorded for audit—same shape whether the actor is human, AI agent, or CI/CD pipeline.

## Supported platforms

| Platform | Minimum version | Arch |
| --- | --- | --- |
| Linux | Ubuntu 18.04+, Debian 11+, RHEL / Rocky / AlmaLinux 8+, Oracle Linux 8+, Amazon Linux 2 / 2023, Fedora (current or previous) | amd64, arm64 |
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

## Service management

### Linux (systemd)

```bash
sudo systemctl status alpamon
sudo systemctl restart alpamon
sudo journalctl -u alpamon -f
```

The unit sets `KillMode=process`, so restarting or stopping alpamon signals only the agent itself, not the whole control-group. Sessions it launched—Websh terminals and detached jobs such as `tmux`, `screen`, or `nohup`'d commands—keep running across a restart, the same way `sshd` leaves active login sessions alone. Reattach to them from a new session after the agent reconnects.

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

## Development

### Build from source

```bash
git clone https://github.com/alpacax/alpamon.git
cd alpamon
go build -o alpamon ./cmd/alpamon         # native
GOOS=windows GOARCH=amd64 go build ./cmd/alpamon   # Windows cross-compile
```

Go 1.25.12+ is required. `GOPATH/bin` should be on `PATH`. The generated Ent code is gitignored, so run `go generate ./pkg/db/ent` (see below) before the first build.

### Generate Ent schema code

Runs `pkg/db/ent/entc.go`, which excludes the unused Atlas SQL dialects from the binary. Do not invoke the ent CLI directly—it regenerates the migrate package and pulls the Atlas dialects back in.

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

### Docker testing (Linux distros)

```bash
./Dockerfiles/build.sh
docker run alpamon:ubuntu-22.04

# Custom workspace
docker run \
    -e ALPACON_URL="https://<workspace>" \
    -e PLUGIN_ID="<plugin_id>" \
    -e PLUGIN_KEY="<plugin_key>" \
    alpamon:latest
```

Covered distros: Ubuntu 22.04/20.04, Debian 11, RHEL 8/9. Legacy Dockerfiles for Ubuntu 18.04, Debian 10, and CentOS 7 also ship under `Dockerfiles/` for best-effort builds against EOL platforms.

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
