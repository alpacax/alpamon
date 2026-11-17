package runner

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
)

const (
	userSyncSentinelURL = "/sentinel/"
	userSyncHash        = "sha256:test"
)

type userWrite struct {
	method   string
	path     string
	syncHash string
	body     map[string]any
}

// fakeUserServer serves remote as the users sync projection and records every write.
type fakeUserServer struct {
	mu       sync.Mutex
	writes   []userWrite
	sentinel chan struct{}
}

func startUserSync(t *testing.T, remote []UserData) (*scheduler.Session, *fakeUserServer) {
	t.Helper()
	fake := &fakeUserServer{sentinel: make(chan struct{})}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/proc/users/sync/":
			_ = json.NewEncoder(w).Encode(remote)
			return
		case r.URL.Path == userSyncSentinelURL:
			close(fake.sentinel)
		case strings.HasPrefix(r.URL.Path, "/api/proc/users/"):
			raw, _ := io.ReadAll(r.Body)
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			fake.mu.Lock()
			fake.writes = append(fake.writes, userWrite{method: r.Method, path: r.URL.Path, syncHash: r.Header.Get("X-Sync-Hash"), body: body})
			fake.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	prevThreads := config.GlobalSettings.HTTPThreads
	config.GlobalSettings.HTTPThreads = 1 // one reporter delivers in queue order, so the sentinel arrives last
	t.Cleanup(func() { config.GlobalSettings.HTTPThreads = prevThreads })

	session := &scheduler.Session{BaseURL: srv.URL, Client: srv.Client()}
	rm := scheduler.StartReporters(session, agent.NewContextManager())
	t.Cleanup(func() { _ = rm.Shutdown(5 * time.Second) })
	return session, fake
}

// syncUsers runs the users sync and returns the writes it sent once the queue has drained.
func syncUsers(t *testing.T, session *scheduler.Session, fake *fakeUserServer, current []UserData) []userWrite {
	t.Helper()
	syncerMap["users"].syncData(session, current, userSyncHash)
	scheduler.Rqueue.Post(userSyncSentinelURL, nil, 80, time.Now().Add(10*time.Millisecond))
	select {
	case <-fake.sentinel:
	case <-time.After(10 * time.Second):
		t.Fatal("queued user writes were not delivered")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]userWrite(nil), fake.writes...)
}

func remoteUser(id, name, shell string) UserData {
	return UserData{ID: id, Username: name, UID: 1000, GID: 1000, Directory: "/home/" + name, Shell: shell}
}

func hostUser(name, shell string, validShells []string) UserData {
	return UserData{Username: name, UID: 1000, GID: 1000, Directory: "/home/" + name, Shell: shell, ValidShells: validShells}
}

func patchedPaths(writes []userWrite) []string {
	var paths []string
	for _, w := range writes {
		if w.method == http.MethodPatch {
			paths = append(paths, w.path)
		}
	}
	return paths
}

func TestUserSyncSendsEveryUserWithTheShellListWhenNoUserChanged(t *testing.T) {
	session, fake := startUserSync(t, []UserData{
		remoteUser("1", "alice", "/bin/zsh"),
		remoteUser("2", "bob", "/bin/bash"),
	})
	shells := []string{"/bin/sh", "/bin/bash"}

	writes := syncUsers(t, session, fake, []UserData{
		hostUser("alice", "/bin/zsh", shells),
		hostUser("bob", "/bin/bash", shells),
	})

	assert.ElementsMatch(t, []string{"/api/proc/users/1/", "/api/proc/users/2/"}, patchedPaths(writes))
	for _, w := range writes {
		assert.ElementsMatch(t, []any{"/bin/sh", "/bin/bash"}, w.body["valid_shells"], w.path)
		assert.Equal(t, userSyncHash, w.syncHash, w.path)
	}
}

func TestUserSyncSendsEveryUserWhenOneUserChangedAlongsideTheShellList(t *testing.T) {
	session, fake := startUserSync(t, []UserData{
		remoteUser("1", "alice", "/bin/zsh"),
		remoteUser("2", "bob", "/bin/bash"),
	})
	shells := []string{"/bin/sh", "/bin/bash", "/bin/fish"}

	writes := syncUsers(t, session, fake, []UserData{
		hostUser("alice", "/bin/zsh", shells),
		hostUser("bob", "/bin/fish", shells),
	})

	assert.ElementsMatch(t, []string{"/api/proc/users/1/", "/api/proc/users/2/"}, patchedPaths(writes))
}

func TestUserSyncSendsOnlyChangedUsersWhenTheShellListIsUnreadable(t *testing.T) {
	session, fake := startUserSync(t, []UserData{
		remoteUser("1", "alice", "/bin/zsh"),
		remoteUser("2", "bob", "/bin/bash"),
	})

	writes := syncUsers(t, session, fake, []UserData{
		hostUser("alice", "/bin/zsh", nil),
		hostUser("bob", "/bin/fish", nil),
	})

	require.Equal(t, []string{"/api/proc/users/2/"}, patchedPaths(writes))
	assert.NotContains(t, writes[0].body, "valid_shells")
	assert.Equal(t, userSyncHash, writes[0].syncHash)
}

func TestUserSyncSendsNothingWhenTheShellListIsUnreadableAndNoUserChanged(t *testing.T) {
	session, fake := startUserSync(t, []UserData{remoteUser("1", "alice", "/bin/zsh")})

	writes := syncUsers(t, session, fake, []UserData{hostUser("alice", "/bin/zsh", nil)})

	assert.Empty(t, writes)
}
