package commandgroup

import (
	"context"
	"sync"
)

type lockKey struct{}

// WithStartLock coordinates PID publication with authorization on platforms
// where the process hierarchy is the only available session identifier.
func WithStartLock(ctx context.Context, lock *sync.RWMutex) context.Context {
	return context.WithValue(ctx, lockKey{}, lock)
}

func LockStart(ctx context.Context) func() {
	if lock, ok := ctx.Value(lockKey{}).(*sync.RWMutex); ok {
		lock.Lock()
		return lock.Unlock
	}
	return func() {}
}
