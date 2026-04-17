//go:build !windows

package updater

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
)

func replaceBinary(newPath, currentPath string) error {
	info, err := os.Stat(currentPath)
	if err != nil {
		return fmt.Errorf("failed to stat current binary: %w", err)
	}

	// Backup current binary for rollback on failure.
	backupPath := currentPath + ".bak"
	if err := copyFile(currentPath, backupPath, info.Mode()); err != nil {
		return fmt.Errorf("failed to backup current binary: %w", err)
	}

	// Stage new binary next to current (same filesystem for atomic rename).
	// Create with 0600 first, then chmod to match current binary (immune to
	// umask).
	stagePath := currentPath + ".new"
	if err := copyFile(newPath, stagePath, 0600); err != nil {
		return fmt.Errorf("failed to stage new binary: %w", err)
	}
	defer func() { _ = os.Remove(stagePath) }()

	if err := os.Chmod(stagePath, info.Mode()); err != nil {
		return fmt.Errorf("failed to set permissions on staged binary: %w", err)
	}

	// Atomic replace. Unix allows renaming over a running executable
	// because file lookups use inodes, not paths.
	if err := os.Rename(stagePath, currentPath); err != nil {
		return fmt.Errorf("failed to rename binary: %w", err)
	}

	_ = os.Remove(backupPath)
	log.Debug().Msg("Binary replaced successfully, backup removed.")
	return nil
}
