//go:build !linux

package updater

func lockUpgrade() bool { return true }

func unlockUpgrade() {}
