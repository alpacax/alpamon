package firewall

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// BackupManager manages firewall state backups for atomic operations with rollback
type BackupManager struct {
	backend    FirewallBackend
	lastBackup string
	backupTime time.Time
	mu         sync.RWMutex
}

// NewBackupManager creates a new backup manager
func NewBackupManager(backend FirewallBackend) *BackupManager {
	return &BackupManager{
		backend: backend,
	}
}

// SetBackend updates the backup manager's backend
func (bm *BackupManager) SetBackend(backend FirewallBackend) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.backend = backend
}

// CreateBackup creates a backup of current firewall state
func (bm *BackupManager) CreateBackup(ctx context.Context) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if bm.backend == nil {
		return fmt.Errorf("no firewall backend configured")
	}

	backup, err := bm.backend.Backup(ctx)
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	bm.lastBackup = backup
	bm.backupTime = time.Now()

	return nil
}

// Rollback restores the last backup
func (bm *BackupManager) Rollback(ctx context.Context) error {
	bm.mu.RLock()
	backup := bm.lastBackup
	backend := bm.backend
	bm.mu.RUnlock()

	if backend == nil {
		return fmt.Errorf("no firewall backend configured")
	}

	if backup == "" {
		return fmt.Errorf("no backup available for rollback")
	}

	if err := backend.Restore(ctx, backup); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	return nil
}

// HasBackup checks if a backup exists
func (bm *BackupManager) HasBackup() bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.lastBackup != ""
}

// GetLastBackup returns the last backup and its timestamp
func (bm *BackupManager) GetLastBackup() (backup string, backupTime time.Time, exists bool) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	if bm.lastBackup == "" {
		return "", time.Time{}, false
	}

	return bm.lastBackup, bm.backupTime, true
}

// ClearBackup clears the stored backup
func (bm *BackupManager) ClearBackup() {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.lastBackup = ""
	bm.backupTime = time.Time{}
}

// BackupAge returns the age of the current backup
func (bm *BackupManager) BackupAge() time.Duration {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	if bm.lastBackup == "" {
		return 0
	}

	return time.Since(bm.backupTime)
}

// WithBackup executes an operation with automatic backup and rollback on failure
func (bm *BackupManager) WithBackup(ctx context.Context, operation func() error) error {
	// Create backup before operation
	if err := bm.CreateBackup(ctx); err != nil {
		return fmt.Errorf("pre-operation backup failed: %w", err)
	}

	// Execute the operation
	if err := operation(); err != nil {
		// Attempt rollback on failure
		if rollbackErr := bm.Rollback(ctx); rollbackErr != nil {
			return fmt.Errorf("operation failed: %w; rollback also failed: %v", err, rollbackErr)
		}
		return fmt.Errorf("operation failed (rolled back): %w", err)
	}

	return nil
}
