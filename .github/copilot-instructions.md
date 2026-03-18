# Copilot instructions

## Project overview

Alpamon is a lightweight Go-based server agent for Alpacon—the infrastructure access platform that provides secure, unified server access for humans, AI agents, and CI/CD pipelines. It establishes an outbound-only WebSocket connection to the Alpacon console, enabling browser-based terminals (Websh), file transfers, system monitoring, and remote command execution. Every action is supervised and audited for compliance. Metrics are stored locally in SQLite (Ent ORM).

## Writing conventions

- **Product names**: Use "Websh" (not "WebSH", "websh", or "WEBSH"). Proper nouns like Alpamon, Alpacon, and Websh should always be capitalized as shown.
- **Sentence case**: Use sentence case for all headings, labels, and documentation (e.g., "Architecture overview" not "Architecture Overview"). Only capitalize the first word and proper nouns.
- **Em-dashes**: No spaces around em-dashes (e.g., "word—word" not "word — word").

## Architecture

Commands flow through a handler-based executor pattern:

1. `pkg/runner/` receives WebSocket commands
2. `pkg/executor/dispatcher.go` routes to registered handlers via registry
3. `pkg/executor/handlers/` contains modular handlers: shell, system, file, firewall, terminal, tunnel, user, group, info
4. `pkg/executor/executor.go` runs system commands with privilege demotion and timeout handling

Key packages:
- `pkg/collector/`—System metric collection (realtime and batch)
- `pkg/db/`—Ent ORM with SQLite backend
- `pkg/agent/`—Centralized lifecycle management
- `internal/protocol/`—Command and message protocol definitions
- `internal/pool/`—Worker pool for concurrent tasks

## Code conventions

- Run `go test -v ./... -p 1` for tests (sequential due to SQLite locking)
- Run Ent code generation after schema changes; never edit `pkg/db/ent/` manually
- Platform-specific files use `_darwin.go` / `_linux.go` suffixes
- Timeout exit code is 124 (GNU `timeout` convention)
- Default shell command timeout is 30 minutes
- Firewall operations: backup state before changes, rollback on failure
