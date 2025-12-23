# Alpamon
New Go-based Secure Server Agent for Alpacon

**Alpamon** is a server agent for **Alpacon**. Each server should have Alpamon installed to be controlled via Alpacon.

This guide outlines the step-by-step process for installing Alpamon within a development environment. The installation requires an active Internet connection or the appropriate configuration of a proxy server.

## System Requirements

To run Alpamon, ensure your system meets the following requirements:
- Operating system: Linux, macOS, or Windows (via WSL)
- Go version: 1.24.4 or higher
- Memory: At least 512MB RAM
- Disk space: At least 100MB free space

## Getting started
To build Alpamon, ensure you have:
- [Go](https://go.dev/doc/install) version 1.24.4 or higher installed(required for building).
  - The module is compatible with Go **1.23** and above for usage (importing and running pre-built binaries).
  - Make sure `$GOPATH` is set and `$GOPATH/bin` is added to your system’s `PATH`.
  
## Installation
Download the latest `alpamon` directly from our releases page or install it using package managers on Linux.

### Linux

#### Debian and Ubuntu
```bash
curl -s https://packagecloud.io/install/repositories/alpacax/alpamon/script.deb.sh?any=true | sudo bash

# Install alpamon (includes PAM module by default)
sudo apt-get install alpamon

# Install without PAM module
sudo apt-get install alpamon --no-install-recommends
```

#### CentOS and RHEL
```bash
curl -s https://packagecloud.io/install/repositories/alpacax/alpamon/script.rpm.sh?any=true | sudo bash

# Install alpamon (includes PAM module by default)
sudo yum install alpamon

# Install without PAM module
sudo yum install alpamon --setopt=install_weak_deps=False
```

### PAM Module

By default, `alpamon` installation includes the `alpamon-pam` package, which provides PAM (Pluggable Authentication Modules) integration for advanced authentication features:
- **pam_alpamon.so**: Verifies Alpacon users during sudo authentication
- **alpacon_approval.so**: Handles sudo command approval requests

#### Configuration
After installation, configure PAM and sudo to enable the authentication features:

1. Add to `/etc/pam.d/sudo`:
```
auth [user_unknown=ignore auth_err=die success=done default=bad] pam_alpamon.so
```

2. Add to `/etc/sudo.conf`:
```
Plugin approval_plugin alpacon_approval.so
```

**Note**: The Alpamon service must be running with socket at `/var/run/alpamon/auth.sock` for PAM authentication to work.

### macOS

#### Clone the source code
To get started on macOS, clone the source code from the repository:
```bash
git clone https://github.com/alpacax/alpamon.git
```

#### Generate Ent Schema Code with Entgo
To generate Ent schema code with custom features, navigate to the root of the project and use the following command:
```bash
go run -mod=mod entgo.io/ent/cmd/ent@v0.14.2 generate --feature sql/modifier --target ./pkg/db/ent ./pkg/db/schema
```

#### Install Atlas CLI (Development Only)
Atlas CLI is **only required for development** when you need to generate new migration files after modifying database schemas in `pkg/db/schema/`. Production deployments do not require Atlas CLI as migrations are executed directly from embedded SQL files.

To install Atlas CLI for development:
```bash
curl -sSf https://atlasgo.sh | sh
```

After modifying Ent schemas, generate migration files:
```bash
atlas migrate diff <migration_name> \
  --dir "file://pkg/db/migration" \
  --to "ent://pkg/db/ent/schema" \
  --dev-url "sqlite://alpamon.db?mode=memory"
```

#### Install Go dependencies
Make sure you have Go installed. Then, navigate to the project root and download the necessary Go packages:
```bash
go mod tidy
```

## Configure

Alpamon can be configured via the files listed below.

- `/etc/alpamon/alpamon.conf`
- `~/.alpamon.conf`

It is recommended to use `/etc/alpamon/alpamon.conf` for deployment, but you can use `~/.alpamon.conf` for development.

```ini
[server]
url = http://localhost:8000
id = 
key = 

[ssl]
verify = true
ca_cert = 

[logging]
debug = true
```

### Configuration details

- `server`: Server settings
    - `url`: The URL for Alpaca Console. If you are in a local development environment, this will be `https://localhost:8000`.
    - `id`: Server ID
    - `key`: Server Key
    - `ca_cert`: Path for the CA certificate
- `logging`: Logging settings
    - `debug`: Whether to print debug logs or not
 
For testing with the `Alpacon-Server`, you can use the following values:
- `url` = `http://localhost:8000`
- `id` = `7a50ea6c-2138-4d3f-9633-e50694c847c4`
- `key` = `alpaca`


## Run

### Local build

To build Alpamon as a binary for local development, run the following command from the project root:
```sh
go build -o alpamon ./cmd/alpamon
```
This will create an `alpamon` executable in your project root. You can run it directly:

```sh
./alpamon
```

### Local environment

To run Alpamon in a local development environment, you can also use Go directly:
```sh
go run ./cmd/alpamon
```

### Docker
You can also use docker to test alpamon in various Linux distributions. We use Docker Desktop to test alpamon on following distributions.

- Ubuntu: 18.04, 20.04, 22.04
- Debian: 10, 11
- RedHat: 8, 9
- CentOS: 7

#### Build
Build docker images with the build script.
```
./Dockerfiles/build.sh
```

#### Run
You can run containers for these images in Docker Desktop or using command line like below.
```
docker run alpamon:ubuntu-22.04
```
- Note: This will run the container with the default workspace URL (http://localhost:8000), plugin ID, and key values. 
For more details, refer to the `entrypoint.sh` file in the Dockerfiles directory corresponding to each operating system.

To run the container with a custom workspace URL, plugin ID, and key, use the following command:
```
docker run \
  -e ALPACON_URL="your_workspace_url" \
  -e PLUGIN_ID="your_plugin_id" \
  -e PLUGIN_KEY="your_plugin_key" \
  alpamon:latest
```
- Replace the environment variable values (your_workspace_url, your_plugin_id, your_plugin_key) with your actual workspace configuration.

### Deploy as a service

For Linux systems supporting `systemd`, you can run `alpamon` as a systemd service. In this case, you need to adapt `alpamon/config/alpamon.service` for your environment.

Specifically, `ExecStart` should be something like `/usr/local/bin/alpamon`.

Run the following commands to prepare system directories.

```sh
sudo cp alpamon/config/tmpfile.conf /usr/lib/tmpfiles.d/alpamon.conf
sudo systemd-tmpfiles --create
```

Run the following commands to install a systemd service.

```sh
sudo cp alpamon/config/alpamon.service /lib/systemd/system/alpamon.service
sudo systemctl daemon-reload
sudo systemctl start alpamon.service
sudo systemctl enable alpamon.service
systemctl status alpamon.service
```

The result would look like the following. The status must be loaded and active (running).

```
alpamon.service - alpamon agent for Alpacon
     Loaded: loaded (/lib/systemd/system/alpamon.service; enabled; vendor preset: enabled)
     Active: active (running) since Thu 2023-09-28 23:48:55 KST; 4 days ago
```

### Logs

Alpamon logs are managed by systemd's journald. Use the following commands to view logs:

```bash
# View all logs
journalctl -u alpamon

# Follow logs in real-time
journalctl -u alpamon -f

# View logs since today
journalctl -u alpamon --since today

# View recent logs (last 100 lines)
journalctl -u alpamon -n 100
```
