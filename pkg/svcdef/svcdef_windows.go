// Package svcdef holds the Windows service identity and recovery defaults shared by
// 'alpamon register', the SCM handler, and the self-update guard, so they never drift.
// Windows-only (every consumer is a _windows.go file); go build ./... skips it elsewhere.
package svcdef

import (
	"time"

	"golang.org/x/sys/windows/svc/mgr"
)

// ServiceName is the Windows Service name registered by 'alpamon register'.
const ServiceName = "alpamon"

const (
	// RecoveryResetSeconds is the SCM window after which the failure count resets.
	RecoveryResetSeconds = 60
	// RecoveryRestartDelay is how long SCM waits before each automatic restart.
	RecoveryRestartDelay = 5 * time.Second
)

// DefaultRecoveryActions is the SCM policy 'alpamon register' installs and the
// self-update guard restores; the trailing NoAction stops a broken binary thrashing SCM.
func DefaultRecoveryActions() []mgr.RecoveryAction {
	return []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: RecoveryRestartDelay},
		{Type: mgr.ServiceRestart, Delay: RecoveryRestartDelay},
		{Type: mgr.NoAction},
	}
}
