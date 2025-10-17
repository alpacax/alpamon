# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Alpamon is a Go-based secure server agent for Alpacon that collects system metrics and executes remote commands. It runs as a daemon that communicates with the Alpacon console via WebSocket connections and stores metrics in a local SQLite database using Ent ORM.

## Development Commands

### Code Generation
```bash
# Generate Ent schema code (required before building)
go run -mod=mod entgo.io/ent/cmd/ent@v0.14.2 generate --feature sql/modifier --target ./pkg/db/ent ./pkg/db/schema

# Alternative using go:generate
go generate ./pkg/db/ent
```

### Building
```bash
# Build the main binary
cd cmd/alpamon
go build -v .

# Install dependencies
go mod tidy
```

### Testing
```bash
# Run all tests with sequential execution
go test -v ./... -p 1

# Run specific package tests
go test -v ./pkg/collector/check/realtime/cpu
```

### Running Locally
```bash
# Run from source (ensure you're in cmd/alpamon directory)
cd cmd/alpamon
go run main.go

# Configuration file locations (in order of precedence):
# - ~/.alpamon.conf (development)
# - /etc/alpamon/alpamon.conf (production)
```

### Docker Testing
```bash
# Build all distribution images
./Dockerfiles/build.sh

# Run specific distribution
docker run alpamon:ubuntu-22.04
```

## Architecture Overview

### Core Components

**Runner Package (`pkg/runner/`)**
- `WebsocketClient`: Maintains WebSocket connection to Alpacon console
- `command.go`: Command execution with privilege escalation/demotion
- `shell.go`: Shell command execution with stdin/stdout handling
- `firewall_backup.go`: Firewall state backup/restore using iptables/nftables
- `ftp.go`: FTP server functionality for file transfers

**Collector Package (`pkg/collector/`)**
- **Realtime collectors**: CPU, memory, disk I/O, network traffic metrics
- **Batch collectors**: Hourly and daily aggregated metrics
- **Scheduler**: Metric collection scheduling and coordination
- **Transporter**: Metric transmission to Alpacon console

**Database Layer (`pkg/db/`)**
- **Ent ORM**: Code-generated database models and queries
- **Schema definitions**: Located in `pkg/db/schema/`
- **Migrations**: Versioned schema changes in `pkg/db/migration/`
- **SQLite backend**: Local storage with automatic migration

**Configuration (`pkg/config/`)**
- INI-based configuration parsing
- Environment variable support
- Multi-location config file loading

### Data Flow

1. **Startup**: Agent initializes database, establishes WebSocket connection
2. **Metric Collection**: Scheduled collectors gather system metrics → local database
3. **Command Execution**: WebSocket receives commands → runner executes → results sent back
4. **Firewall Management**: Backup/restore operations for iptables/nftables rules
5. **FTP Operations**: File transfer capabilities with authentication

### Security Architecture

**Privilege Management**
- Root execution for system-level operations
- User demotion for safer command execution
- PID file management and signal handling

**Firewall Operations**
- State backup before rule changes
- Automatic rollback on failure
- Support for both iptables and nftables

**Input Validation**
- Command argument sanitization in runner package
- WebSocket message validation
- Configuration parameter validation

## Key Patterns

### Command Execution
```go
// Standard command execution
exitCode, output := runCmdWithOutput([]string{"command", "args"}, user, group, env, timeout)

// Command with stdin input (for firewall rules, etc.)
exitCode, output := runCmdWithOutputAndInput([]string{"command"}, inputData, user, group, env, timeout)
```

### Database Operations
```go
// Ent client usage
client := db.InitDB()
cpu := client.CPU.Create().SetUsage(usage).SetTimestamp(time.Now()).SaveX(ctx)
```

### Metric Collection
- Collectors implement `Check` interface with `Collect()` method
- Realtime: Direct system calls using `gopsutil`
- Batch: Database aggregation queries for hourly/daily summaries

### WebSocket Communication
- JSON message protocol with command/response pattern
- Automatic reconnection with exponential backoff
- Context-based cancellation for graceful shutdown

## Important Implementation Notes

**Ent Code Generation**: Always run Ent code generation after schema changes. The generated code in `pkg/db/ent/` should not be manually edited.

**Testing Constraints**: Tests run with `-p 1` (sequential execution) due to SQLite database file locking and system resource measurement conflicts.

**Platform Compatibility**: Codebase includes platform-specific implementations (darwin/linux) for PTY and PID file operations.

**Firewall Operations**: Use `runCmdWithOutputAndInput` for piping rules via stdin to `nft -f -` and `iptables-restore` commands.

**Database Migrations**: Use Atlas CLI for schema migrations. Migration files are in `pkg/db/migration/` with checksums in `atlas.sum`.