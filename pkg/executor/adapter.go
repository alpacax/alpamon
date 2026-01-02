package executor

import (
	"github.com/alpacax/alpamon/pkg/scheduler"
)

// SystemInfoAdapter implements the common.SystemInfoManager interface for handlers
type SystemInfoAdapter struct {
	session    *scheduler.Session
	commitFunc func()
	syncFunc   func(*scheduler.Session, []string)
}

// NewSystemInfoAdapter creates a new system info adapter with function callbacks
func NewSystemInfoAdapter(
	session *scheduler.Session,
	commitFunc func(),
	syncFunc func(*scheduler.Session, []string),
) *SystemInfoAdapter {
	return &SystemInfoAdapter{
		session:    session,
		commitFunc: commitFunc,
		syncFunc:   syncFunc,
	}
}

// CommitSystemInfo implements common.SystemInfoManager
func (a *SystemInfoAdapter) CommitSystemInfo() {
	if a.commitFunc != nil {
		a.commitFunc()
	}
}

// SyncSystemInfo implements common.SystemInfoManager
func (a *SystemInfoAdapter) SyncSystemInfo(keys []string) {
	if a.syncFunc != nil {
		a.syncFunc(a.session, keys)
	}
}
