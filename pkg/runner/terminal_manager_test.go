//go:build !windows

package runner

import (
	"fmt"
	"sync"
	"testing"

	"github.com/creack/pty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminalManager_RegisterAndGet(t *testing.T) {
	m := NewTerminalManager(nil)
	pc := &PtyClient{sessionID: "test-session"}

	m.Register("test-session", pc)

	got := m.Get("test-session")
	assert.Same(t, pc, got)

	got = m.Get("nonexistent")
	assert.Nil(t, got)
}

func TestTerminalManager_Remove(t *testing.T) {
	m := NewTerminalManager(nil)
	pc := &PtyClient{sessionID: "test-session"}

	m.Register("test-session", pc)
	m.Remove("test-session")

	got := m.Get("test-session")
	assert.Nil(t, got)
}

func TestTerminalManager_Resize_InvalidSession(t *testing.T) {
	m := NewTerminalManager(nil)

	err := m.Resize("nonexistent", 40, 120)
	assert.EqualError(t, err, "invalid session ID")
}

func TestTerminalManager_Refresh_InvalidSession(t *testing.T) {
	m := NewTerminalManager(nil)

	err := m.Refresh("nonexistent")
	assert.EqualError(t, err, "invalid session ID")
}

// TestTerminalManager_ConcurrentRegisterGetRemove exercises concurrent map
// access. Run with -race to verify no data race on the terminals map.
func TestTerminalManager_ConcurrentRegisterGetRemove(t *testing.T) {
	m := NewTerminalManager(nil)
	const n = 50

	var wg sync.WaitGroup
	wg.Add(n * 3)

	for i := range n {
		id := fmt.Sprintf("session-%d", i)
		pc := &PtyClient{sessionID: id}

		go func() {
			defer wg.Done()
			m.Register(id, pc)
		}()
		go func() {
			defer wg.Done()
			m.Get(id)
		}()
		go func() {
			defer wg.Done()
			m.Remove(id)
		}()
	}

	wg.Wait()
}

// TestTerminalManager_ConcurrentResizeAndRemove simulates the real race
// scenario: a handler calling Resize (read lock) while close() calls Remove
// (write lock) followed by ptmx.Close(). With proper locking, Remove waits
// for the in-flight Resize to finish before the PTY fd is closed.
// Run with -race to verify no data race on ptmx access.
func TestTerminalManager_ConcurrentResizeAndRemove(t *testing.T) {
	m := NewTerminalManager(nil)

	ptmx, tty, err := pty.Open()
	require.NoError(t, err)
	defer func() { _ = tty.Close() }()

	pc := &PtyClient{sessionID: "test", ptmx: ptmx}
	m.Register("test", pc)

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: repeatedly resize (holds read lock during syscall)
	go func() {
		defer wg.Done()
		for i := range 100 {
			_ = m.Resize("test", uint16(20+i%10), 80)
		}
	}()

	// Goroutine 2: simulate close() — Remove then close ptmx
	go func() {
		defer wg.Done()
		m.Remove("test")
		_ = ptmx.Close()
	}()

	wg.Wait()
}

func TestTerminalManager_TrackPID_MapsOnInjectedAuthManager(t *testing.T) {
	prev := SwapAuthManager(nil) // The package global must play no part.
	t.Cleanup(func() { SwapAuthManager(prev) })
	am := newTestAuthManager()
	m := NewTerminalManager(am)

	m.trackPID(4242, &SessionInfo{SessionID: "s1", PID: 4242})

	entry, ok := am.LookupPID(4242)
	require.True(t, ok, "PID mapping missing after trackPID")
	assert.Equal(t, "s1", entry.SessionID)
}

func TestTerminalManager_TrackPID_NoopWithoutAuthManager(t *testing.T) {
	m := NewTerminalManager(nil)

	assert.NotPanics(t, func() {
		m.trackPID(4242, &SessionInfo{SessionID: "s1", PID: 4242})
		m.untrackPID(4242)
	})
}
