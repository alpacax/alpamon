# Copilot instructions

## Project overview

Alpamon is a lightweight Go-based server agent for Alpacon—the infrastructure access platform that provides secure, unified server access for humans, AI agents, and CI/CD pipelines. It establishes an outbound-only WebSocket connection to the Alpacon console, enabling browser-based terminals (Websh), file transfers, system monitoring, and remote command execution. Every action is supervised and audited for compliance. Metrics are stored locally in SQLite (Ent ORM).

## Writing conventions

- **Product names**: Use "Websh" (not "WebSH", "websh", or "WEBSH"). Proper nouns like Alpamon, Alpacon, and Websh should always be capitalized as shown.
- **Sentence case**: Use sentence case for all headings, labels, and documentation (e.g., "Architecture overview" not "Architecture Overview"). Only capitalize the first word and proper nouns.
- **Em-dashes**: No spaces around em-dashes (e.g., "word—word" not "word — word"). Use colons instead of em-dashes for itemized descriptions (e.g., "`shell/`: description").

## Architecture

Commands flow through a handler-based executor pattern:

1. `pkg/runner/` receives WebSocket commands
2. `pkg/executor/dispatcher.go` routes to registered handlers via registry
3. `pkg/executor/handlers/` contains modular handlers: shell, system, file, firewall, terminal, tunnel, user, group, info
4. `pkg/executor/executor.go` runs system commands with privilege demotion and timeout handling

Key packages:
- `pkg/collector/`: System metric collection (realtime and batch)
- `pkg/db/`: Ent ORM with SQLite backend
- `pkg/agent/`: Centralized lifecycle management
- `internal/protocol/`: Command and message protocol definitions
- `internal/pool/`: Worker pool for concurrent tasks

## Code conventions

- Run `go test -v ./... -p 1` for tests (sequential due to SQLite locking)
<!-- This testing-conventions paragraph is mirrored in CLAUDE.md, README.md and .github/copilot-instructions.md. Edit all three together. -->
- Assert with testify: `require` when a failed check makes the rest of the test meaningless, `assert` for the checks themselves. Prefer the specific helper over a hand-rolled comparison: `require.NoError`, `assert.ErrorContains`, `assert.DirExists`. Read what a helper accepts before reaching for it, because the shorter spelling is sometimes the weaker check: `assert.NoFileExists` treats a directory at the path, and any other `Lstat` error, as absence, so a test that must prove a path was removed asserts `os.ErrNotExist` from `os.Stat` instead. New tests never call `t.Error`, `t.Errorf`, `t.Fatal` or `t.Fatalf` directly; the single exception is a bare `t.Fatal` where there is no error value to assert on, such as the timeout branch of a `select`
- A test that waits on a timer belongs in a `testing/synctest` bubble: inside `synctest.Test` the clock is fake and advances only once every goroutine in the bubble is blocked, so a timeout guard fires on a real block instead of on a slow runner, and a `wg.Wait` the code under test can no longer satisfy surfaces as a deadlock rather than as a package timeout. Reach for a fixed `time.Sleep` only to hold a worker so jobs overlap. Tests backed by `httptest`, a PTY, or a real socket stay on the real clock, because a bubble does not count those waits as blocked
- Run Ent code generation after schema changes; never edit `pkg/db/ent/` manually
- Platform-specific files use `_darwin.go` / `_linux.go` suffixes
- Timeout exit code is 124 (GNU `timeout` convention)
- Default shell command timeout is 30 minutes
- Firewall operations: backup state before changes, rollback on failure
