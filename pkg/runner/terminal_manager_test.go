package runner

import (
	"testing"
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
