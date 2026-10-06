//go:build linux

package updater

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/rs/zerolog/log"
)

// scripts/postinstall.sh takes the same file before it restarts the agent.
var upgradeLockPath = "/run/alpamon/upgrade.lock"

var (
	upgradeLockMu   sync.Mutex
	upgradeLockFile *os.File
)

// lockUpgrade reports false only when another process holds the lock. Go opens the file
// O_CLOEXEC, so a syscall.Exec restart drops it. Any other failure proceeds unlocked.
func lockUpgrade() bool {
	upgradeLockMu.Lock()
	defer upgradeLockMu.Unlock()
	if upgradeLockFile != nil {
		return true
	}
	if err := os.MkdirAll(filepath.Dir(upgradeLockPath), 0o750); err != nil {
		log.Warn().Err(err).Msg("Failed to create the upgrade lock directory; continuing without it.")
		return true
	}
	f, err := os.OpenFile(upgradeLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to open the upgrade lock; continuing without it.")
		return true
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return false
		}
		log.Warn().Err(err).Msg("Failed to lock the upgrade lock; continuing without it.")
		return true
	}
	upgradeLockFile = f
	return true
}

func unlockUpgrade() {
	upgradeLockMu.Lock()
	defer upgradeLockMu.Unlock()
	if upgradeLockFile != nil {
		_ = upgradeLockFile.Close()
		upgradeLockFile = nil
	}
}
