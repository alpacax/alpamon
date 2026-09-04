//go:build windows

package runner

import (
	"context"
	"errors"
)

// Editor tunnels are rejected on Windows before they reach this code
// (editorTunnelSupported, pkg/executor/handlers/tunnel/tunnel.go), so neither
// function below is reachable today. Both refuse rather than fall back to
// path-based MkdirAll and WriteFile, which nothing here would protect: the
// agent runs as LocalSystem, and a directory junction, which any user can
// create without the privilege a symlink requires, redirects a path-based
// write the same way a symlink does on Unix. Whoever enables editor tunnels on
// Windows (#379) writes the junction-safe counterpart of editor_unix.go here
// first, and editor_windows_test.go is what says so.

var errUserDataDirUnsupported = errors.New("code-server user data dir is not implemented on Windows")

func setupUserDataFiles(ctx context.Context, homeDir, dirName string, configData, settingsData []byte) error {
	return errUserDataDirUnsupported
}

func chownTreeNoFollow(ctx context.Context, root string, uid, gid int) error {
	return errUserDataDirUnsupported
}
