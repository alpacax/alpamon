//go:build !windows

package commandcancel

import "sync"

// heldLeaders are the children alpamon started and has not yet reaped. An
// unreaped child, a zombie included, keeps its PID, so no other process can
// take that number as its PGID or SID.
var heldLeaders = struct {
	mu sync.Mutex
	m  map[int]*heldLeader
}{m: map[int]*heldLeader{}}

type heldLeader struct {
	mu       sync.RWMutex
	released bool
}

// HoldLeader records pid, a child alpamon has just started, until
// ReapLeader reaps it. Every reap of pid must then go through ReapLeader.
func HoldLeader(pid int) {
	if pid <= 1 {
		return
	}
	heldLeaders.mu.Lock()
	defer heldLeaders.mu.Unlock()
	heldLeaders.m[pid] = &heldLeader{}
}

// ReapLeader runs reap, the reap of a pid HoldLeader recorded, once every
// signal relying on the unreaped pid has been delivered. No such signal
// starts afterwards, so a caller that reaps a leader still running gives up
// signalling its group from then on.
func ReapLeader(pid int, reap func() error) error {
	heldLeaders.mu.Lock()
	leader := heldLeaders.m[pid]
	delete(heldLeaders.m, pid)
	heldLeaders.mu.Unlock()
	if leader != nil {
		leader.mu.Lock()
		leader.released = true
		leader.mu.Unlock()
	}
	return reap()
}

// withHeldLeader runs signal only while pid is held unreaped and reports
// whether it ran. The pid cannot be reaped while signal runs.
func withHeldLeader(pid int, signal func() error) (bool, error) {
	heldLeaders.mu.Lock()
	leader := heldLeaders.m[pid]
	heldLeaders.mu.Unlock()
	if leader == nil {
		return false, nil
	}
	leader.mu.RLock()
	defer leader.mu.RUnlock()
	if leader.released {
		return false, nil
	}
	return true, signal()
}
