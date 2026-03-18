# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

Alpamon is a lightweight Go-based server agent for Alpacon—the infrastructure access platform that provides secure, unified server access for humans, AI agents, and CI/CD pipelines. Installed on each server, it establishes an outbound-only WebSocket connection to the Alpacon console, enabling browser-based terminals (Websh), file transfers, system monitoring, and remote command execution without VPNs or SSH keys. Every action is supervised and audited for compliance. It stores metrics locally in SQLite using Ent ORM.

## Writing conventions

- **Product names**: Use "Websh" (not "WebSH", "websh", or "WEBSH"). Proper nouns like Alpamon, Alpacon, and Websh should always be capitalized as shown.
- **Sentence case**: Use sentence case for all headings, labels, and documentation (e.g., "Architecture overview" not "Architecture Overview"). Only capitalize the first word and proper nouns.
- **Em-dashes**: No spaces around em-dashes (e.g., "word—word" not "word — word"). Use colons instead of em-dashes for itemized descriptions (e.g., "`shell/`: description").

## Development commands

### Code generation
```bash
# Generate Ent schema code (required before building)
go run -mod=mod entgo.io/ent/cmd/ent@v0.14.5 generate --feature sql/modifier --target ./pkg/db/ent ./pkg/db/schema

# Alternative using go:generate
go generate ./pkg/db/ent
```

### Database schema changes (development only)
```bash
# Install Atlas CLI (only needed for generating new migration files)
curl -sSf https://atlasgo.sh | sh

# After modifying schemas in pkg/db/schema/, generate migration file
atlas migrate diff <migration_name> \
  --dir "file://pkg/db/migration" \
  --to "ent://pkg/db/ent/schema" \
  --dev-url "sqlite://alpamon.db?mode=memory"

# Note: Atlas CLI is NOT required for production - migrations are executed
# directly from embedded SQL files in pkg/db/migration/
```

### Building
```bash
# Build the main binary
go build -v ./cmd/alpamon

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

### Running locally
```bash
# Run from source
go run ./cmd/alpamon

# Configuration file locations (in order of precedence):
# - ~/.alpamon.conf (development)
# - /etc/alpamon/alpamon.conf (production)
```

### Docker testing
```bash
# Build all distribution images
./Dockerfiles/build.sh

# Run specific distribution
docker run alpamon:ubuntu-22.04
```

## Architecture overview

### Command execution (executor pattern)

Commands from the Alpacon console flow through:

1. `pkg/runner/` receives WebSocket commands and dispatches them
2. `pkg/executor/dispatcher.go` routes commands to registered handlers via the registry
3. `pkg/executor/handlers/` contains modular handlers for each command domain:
   - `shell/`: Shell command execution (supports `/bin/sh -c` via `allow_sh` flag)
   - `system/`: System operations (upgrade, restart, reboot, shutdown)
   - `file/`: File upload/download
   - `firewall/`: Firewall rule management (iptables/nftables)
   - `terminal/`: PTY session management
   - `tunnel/`: Tunnel operations
   - `user/`: User management
   - `group/`: Group management
   - `info/`: System info queries (ping, help, commit, sync)
   - `common/`: Shared interfaces, types, base handler, and test utilities
4. `pkg/executor/executor.go` runs system commands with privilege demotion, environment setup, and timeout handling (exit code 124 on timeout)

### Core packages

**Runner (`pkg/runner/`)**
- `WebsocketClient`: WebSocket connection to Alpacon console
- `command.go`: Command dispatch to executor handlers
- `ftp.go`: FTP server for file transfers
- `terminal_manager.go`: PTY session lifecycle
- `tunnel_client.go`, `tunnel_daemon.go`: Tunnel operations
- `auth_manager.go`: PAM authentication and sudo approval

**Collector (`pkg/collector/`)**
- `check/realtime/`: CPU, memory, disk I/O, network traffic (via gopsutil)
- `check/batch/hourly/`, `check/batch/daily/`: Aggregated metrics
- `scheduler/`: Collection scheduling
- `transporter/`: Metric transmission to Alpacon console

**Database (`pkg/db/`)**
- Ent ORM with code-generated models (`pkg/db/ent/`)
- Schema definitions in `pkg/db/schema/`
- Versioned SQL migrations in `pkg/db/migration/`
- SQLite backend with automatic migration

**Agent (`pkg/agent/`)**
- `ContextManager`: Centralized lifecycle and graceful shutdown

**Internal packages (`internal/`)**
- `protocol/`: Command and message protocol definitions
- `pool/`: Worker pool for concurrent task execution

**Configuration (`pkg/config/`)**
- INI-based configuration parsing
- Environment variable support

### Data flow

1. **Startup**: Agent initializes database, establishes WebSocket connection
2. **Metric collection**: Scheduled collectors gather system metrics → local database
3. **Command execution**: WebSocket receives commands → dispatcher routes to handler → results sent back
4. **Firewall management**: Backup/restore operations for iptables/nftables rules
5. **File transfers**: FTP server with authentication

### Security architecture

- Root execution for system-level operations
- User privilege demotion for safer command execution
- Firewall state backup before rule changes with automatic rollback on failure
- Command argument validation in executor handlers
- JSON message parsing and envelope checks via protocol package
- PID file management and signal handling

## Key patterns

### Handler-based command execution
```go
// Handlers implement the common.Handler interface
type Handler interface {
    Name() string
    Commands() []string
    Execute(ctx context.Context, cmd string, args *CommandArgs) (int, string, error)
    Validate(cmd string, args *CommandArgs) error
}

// Handlers are registered in the factory and dispatched via registry
dispatcher := executor.NewCommandDispatcher(pool, ctxManager)
```

### Database operations
```go
// Ent client usage
client := db.InitDB()
cpu := client.CPU.Create().SetUsage(usage).SetTimestamp(time.Now()).SaveX(ctx)
```

### Metric collection
- Collectors implement `Check` interface with `Collect()` method
- Realtime: Direct system calls using gopsutil
- Batch: Database aggregation queries for hourly/daily summaries

### WebSocket communication
- JSON message protocol with command/response pattern
- Automatic reconnection with exponential backoff
- Context-based cancellation for graceful shutdown

## Important implementation notes

**Ent code generation**: Always run Ent code generation after schema changes. The generated code in `pkg/db/ent/` should not be manually edited.

**Testing constraints**: Tests run with `-p 1` (sequential execution) due to SQLite database file locking and system resource measurement conflicts.

**Platform compatibility**: Codebase includes platform-specific implementations (darwin/linux) for PTY and PID file operations.

**Firewall operations**: Use executor's `RunWithInput` for piping rules via stdin to `nft -f -` and `iptables-restore` commands.

**Database migrations**: Migration system uses direct SQL execution via Go's `database/sql` package. Migration files in `pkg/db/migration/` are pure SQLite SQL. The `RunMigration()` function tracks applied migrations in the `atlas_schema_revisions` table and executes unapplied migrations in transactions. No external tools required.

**Timeout handling**: Commands that exceed their timeout return exit code 124 with an elapsed time message, matching the GNU `timeout` convention. Default shell command timeout is 30 minutes.
