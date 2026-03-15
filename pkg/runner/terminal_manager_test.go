package runner

import (
	"fmt"
	"sync"
	"testing"

	"github.com/creack/pty"
)

func TestTerminalManager_RegisterAndGet(t *testing.T) {
	m := NewTerminalManager()
	pc := &PtyClient{sessionID: "test-session"}

	m.Register("test-session", pc)

	got := m.Get("test-session")
	if got != pc {
		t.Errorf("Get() = %v, want %v", got, pc)
	}

	got = m.Get("nonexistent")
	if got != nil {
		t.Errorf("Get(nonexistent) = %v, want nil", got)
	}
}

func TestTerminalManager_Remove(t *testing.T) {
	m := NewTerminalManager()
	pc := &PtyClient{sessionID: "test-session"}

	m.Register("test-session", pc)
	m.Remove("test-session")

	got := m.Get("test-session")
	if got != nil {
		t.Errorf("Get() after Remove = %v, want nil", got)
	}
}

func TestTerminalManager_Resize_InvalidSession(t *testing.T) {
	m := NewTerminalManager()

	err := m.Resize("nonexistent", 40, 120)
	if err == nil {
		t.Error("Resize() expected error for invalid session")
	}
	if err.Error() != "invalid session ID" {
		t.Errorf("Resize() error = %q, want %q", err.Error(), "invalid session ID")
	}
}

func TestTerminalManager_Refresh_InvalidSession(t *testing.T) {
	m := NewTerminalManager()

	err := m.Refresh("nonexistent")
	if err == nil {
		t.Error("Refresh() expected error for invalid session")
	}
	if err.Error() != "invalid session ID" {
		t.Errorf("Refresh() error = %q, want %q", err.Error(), "invalid session ID")
	}
}

// TestTerminalManager_ConcurrentRegisterGetRemove exercises concurrent map
// access. Run with -race to verify no data race on the terminals map.
func TestTerminalManager_ConcurrentRegisterGetRemove(t *testing.T) {
	m := NewTerminalManager()
	const n = 50

	var wg sync.WaitGroup
	wg.Add(n * 3)

	for i := 0; i < n; i++ {
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
	m := NewTerminalManager()

	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tty.Close() }()

	pc := &PtyClient{sessionID: "test", ptmx: ptmx}
	m.Register("test", pc)

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: repeatedly resize (holds read lock during syscall)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
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
