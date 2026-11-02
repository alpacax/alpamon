# Review rules

WALL-D and Copilot code review apply these rules on top of the Go stack's review criteria.

- Flag firewall changes that do not back up state before changing rules or do not roll back on failure: a failed change can leave the host without its rules.
- Flag process termination by PID or image name instead of a handle, job object or process group the code created: it can kill an unrelated process.
- Flag imports in `pkg/wsclient` outside the standard library, gorilla/websocket, `pkg/tunnel` and `pkg/version`: the `leaf-guard` job fails.
- Flag platform-specific code that lacks the appropriate `_darwin.go`, `_linux.go` or `_windows.go` suffix or build-tagged `_unix.go` (`!windows`) or `_other.go` fallback, or duplicates an existing shared implementation per OS: code can compile on the wrong platform or a fix can leave another OS's copy broken.
