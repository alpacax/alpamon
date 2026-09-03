//go:build windows

package runner

import (
	"os"
	"path/filepath"
)

// Editor tunnels are rejected on Windows before they reach this code
// (editorTunnelSupported, pkg/executor/handlers/tunnel/tunnel.go), which is the
// only reason neither function below is exploitable today.
//
// chownTreeNoFollow is inert: os.Lchown always fails with EWINDOWS here.
// setupUserDataFiles is not — it really creates and writes the files, with no
// defense matching the openat/O_NOFOLLOW walk in editor_unix.go. Before
// code-server support lands (#379) it needs one: the agent runs as LocalSystem,
// and a directory junction, which any user can create without the privilege a
// symlink requires, redirects MkdirAll and WriteFile the same way a symlink
// does on unix.

func setupUserDataFiles(homeDir, dirName string, configData, settingsData []byte) error {
	userDataDir := filepath.Join(homeDir, dirName)
	userDir := filepath.Join(userDataDir, userDataUserDir)

	if err := os.MkdirAll(userDir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(userDataDir, userDataConfigFile), configData, 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(userDir, userDataSettingsFile), settingsData, 0644)
}

func chownTreeNoFollow(root string, uid, gid int) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, uid, gid)
	})
}
