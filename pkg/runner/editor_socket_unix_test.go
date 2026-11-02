//go:build !windows

package runner

import (
	"bufio"
	"bytes"
	"context"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xtaci/smux"
)

func TestEditorSessionDirectory(t *testing.T) {
	for _, stale := range []string{"absent", "directory", "symlink"} {
		t.Run(stale, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "session")
			target := filepath.Join(base, "untouched")
			require.NoError(t, os.Mkdir(target, 0755))
			marker := filepath.Join(target, "marker")
			require.NoError(t, os.WriteFile(marker, []byte("keep"), 0600))
			switch stale {
			case "directory":
				require.NoError(t, os.Mkdir(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "stale"), nil, 0600))
			case "symlink":
				require.NoError(t, os.Symlink(target, dir))
			}
			called := false
			chown := func(path string, uid, gid int) error {
				called = true
				assert.Equal(t, dir, path)
				assert.Equal(t, os.Getuid(), uid)
				assert.Equal(t, os.Getgid(), gid)
				if os.Geteuid() == 0 {
					return os.Lchown(path, uid, gid)
				}
				return nil
			}
			require.NoError(t, createEditorSessionDir(dir, os.Getuid(), os.Getgid(), chown))
			assert.True(t, called)
			info, err := os.Lstat(dir)
			require.NoError(t, err)
			assert.True(t, info.IsDir())
			assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
			stat := info.Sys().(*syscall.Stat_t)
			assert.Equal(t, uint32(os.Getuid()), stat.Uid)
			assert.Equal(t, uint32(os.Getgid()), stat.Gid)
			_, err = os.Stat(filepath.Join(dir, "stale"))
			assert.ErrorIs(t, err, os.ErrNotExist)
			assert.FileExists(t, marker)
			root, err := openEditorDirectory(base)
			require.NoError(t, err)
			m := &CodeServerManager{socketPath: filepath.Join(dir, "cs.sock"), socketRoot: root}
			m.removeSocketDir()
			_, err = os.Lstat(dir)
			assert.ErrorIs(t, err, os.ErrNotExist)
			assert.FileExists(t, marker)
		})
	}
	t.Run("ownership failure removes directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "session")
		err := createEditorSessionDir(dir, 123, 456, func(string, int, int) error { return os.ErrPermission })
		assert.ErrorIs(t, err, os.ErrPermission)
		_, err = os.Lstat(dir)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestEditorSocketBase(t *testing.T) {
	base := filepath.Join(t.TempDir(), "base")
	target := t.TempDir()
	require.NoError(t, os.Symlink(target, base))
	require.Error(t, ensureEditorSocketBase(base))
	require.NoError(t, os.Remove(base))
	sibling := filepath.Join(filepath.Dir(base), "sibling")
	require.NoError(t, os.Mkdir(sibling, 0711))
	require.NoError(t, os.Symlink("sibling", base))
	require.Error(t, ensureEditorSocketBase(base))
	require.NoError(t, os.Remove(base))

	if os.Geteuid() != 0 {
		require.NoError(t, os.Mkdir(base, 0711))
		assert.NoError(t, ensureEditorSocketBase(base))
		return
	}
	require.NoError(t, ensureEditorSocketBase(base))
	info, err := os.Lstat(base)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0711), info.Mode().Perm())
	assert.Zero(t, info.Sys().(*syscall.Stat_t).Uid)
	require.NoError(t, os.Chown(base, 123, 456))
	assert.Error(t, ensureEditorSocketBase(base))
}

func TestEditorStreamsUsePrivateSocket(t *testing.T) {
	for _, metadata := range []string{`{}`, `{"remote_port":"9090"}`, `{"health_check":true}`} {
		t.Run(metadata, func(t *testing.T) {
			// Keep the path below the Unix socket length limit even with long test names.
			dir, err := os.MkdirTemp("", "editor-")
			require.NoError(t, err)
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			socket := filepath.Join(dir, "cs.sock")
			ln, err := net.Listen("unix", socket)
			require.NoError(t, err)
			defer ln.Close()
			require.NoError(t, ln.(*net.UnixListener).SetDeadline(time.Now().Add(5*time.Second)))
			tc := &TunnelClient{clientType: ClientTypeEditor, ctx: t.Context(), codeServerMgr: &CodeServerManager{ctx: t.Context(), socketPath: socket, status: CodeServerStatusReady}}
			require.NoError(t, tc.startSessionRelay())
			assert.Nil(t, tc.daemonCmd)
			left, right := net.Pipe()
			client, err := smux.Client(left, nil)
			require.NoError(t, err)
			defer client.Close()
			server, err := smux.Server(right, nil)
			require.NoError(t, err)
			defer server.Close()
			stream, err := server.OpenStream()
			require.NoError(t, err)
			defer stream.Close()
			require.NoError(t, stream.SetDeadline(time.Now().Add(5*time.Second)))
			done := make(chan struct{})
			go func() {
				defer close(done)
				incoming, acceptErr := client.AcceptStream()
				if acceptErr == nil {
					tc.handleStream(incoming)
				}
			}()
			_, err = io.WriteString(stream, metadata+"\n")
			require.NoError(t, err)
			conn, err := ln.Accept()
			require.NoError(t, err, "editor streams must dial the private socket")
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			if metadata == `{"health_check":true}` {
				response, err := io.ReadAll(stream)
				require.NoError(t, err)
				assert.Contains(t, string(response), `"status":"ready"`)
			} else {
				_, err = io.WriteString(stream, "editor request\n")
				require.NoError(t, err)
				request, err := bufio.NewReader(conn).ReadString('\n')
				require.NoError(t, err)
				assert.Equal(t, "editor request\n", request, "no TCP daemon target header may reach code-server")
				_, err = io.WriteString(conn, "editor response\n")
				require.NoError(t, err)
				response, err := bufio.NewReader(stream).ReadString('\n')
				require.NoError(t, err)
				assert.Equal(t, "editor response\n", response)
			}
			require.NoError(t, stream.Close())
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("stream handler did not finish")
			}
		})
	}
}

func TestEditorReadinessUsesPrivateSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "editor-ready-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "cs.sock")
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer ln.Close()
	m := &CodeServerManager{ctx: t.Context(), socketPath: socket}
	require.NoError(t, m.waitForReady(make(chan struct{})))
}

func TestEditorSocketRejectsDifferentPeerUID(t *testing.T) {
	dir, err := os.MkdirTemp("", "editor-peer-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	target := filepath.Join(dir, "other.sock")
	ln, err := net.Listen("unix", target)
	require.NoError(t, err)
	defer ln.Close()
	socket := filepath.Join(dir, "cs.sock")
	require.NoError(t, os.Symlink(target, socket))
	m := &CodeServerManager{ctx: t.Context(), socketPath: socket,
		procAttr: &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(os.Geteuid() + 1)}}}
	conn, err := m.dialSocket()
	require.ErrorContains(t, err, "differs from editor uid")
	assert.Nil(t, conn)
	require.NoError(t, ln.(*net.UnixListener).SetDeadline(time.Now().Add(5*time.Second)))
	peer, err := ln.Accept()
	require.NoError(t, err)
	defer peer.Close()
	require.NoError(t, peer.SetDeadline(time.Now().Add(5*time.Second)))
	data, err := io.ReadAll(peer)
	require.NoError(t, err)
	assert.Empty(t, data, "no data is sent to a peer with a different uid")
}

func TestEditorSocketSweepDoesNotFollowLinks(t *testing.T) {
	base := t.TempDir()
	target := t.TempDir()
	marker := filepath.Join(target, "keep")
	require.NoError(t, os.WriteFile(marker, nil, 0600))
	require.NoError(t, os.Mkdir(filepath.Join(base, "stale"), 0700))
	require.NoError(t, os.Symlink(target, filepath.Join(base, "link")))
	require.NoError(t, sweepEditorSocketBase(base))
	_, err := os.Lstat(filepath.Join(base, "stale"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.FileExists(t, marker)
}

func TestEditorStartsOnSocketAndReportsExit(t *testing.T) {
	if runtime.GOOS == "darwin" && os.Geteuid() == 0 {
		t.Skip("root code-server path ignores PATH on darwin")
	}
	exe, err := os.Executable()
	require.NoError(t, err)
	dir, err := os.MkdirTemp("/tmp", "es-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	bin := filepath.Join(dir, "code-server")
	script := "#!/bin/sh\nALPAMON_EDITOR_SOCKET_HELPER=1 exec '" + strings.ReplaceAll(exe, "'", "'\\''") + "' -test.run=^TestEditorSocketProcessHelper$ -- \"$@\"\n"
	require.NoError(t, os.WriteFile(bin, []byte(script), 0700))
	t.Setenv("PATH", dir)
	usr, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	m := &CodeServerManager{ctx: ctx, cancel: cancel, username: usr.Username, homeDir: dir,
		socketPath: filepath.Join(dir, "session", "cs.sock"), status: CodeServerStatusIdle,
		stopGrace: time.Second, terminateFn: terminateProcess,
		prepareSocketDir: func(m *CodeServerManager) error {
			return prepareTestEditorSocketDir(m, os.Geteuid(), os.Getegid(), os.Lchown)
		}}
	defer m.Stop()
	require.NoError(t, m.doStart())
	status, lastError := m.Status()
	assert.Equal(t, CodeServerStatusReady, status)
	assert.Empty(t, lastError)
	conn, err := m.dialSocket()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	assert.Eventually(t, func() bool {
		status, msg := m.Status()
		return status == CodeServerStatusError && msg == "code-server exited"
	}, 5*time.Second, 10*time.Millisecond)
	assert.Eventually(t, func() bool { _, err := os.Stat(filepath.Dir(m.socketPath)); return os.IsNotExist(err) }, 5*time.Second, 10*time.Millisecond)
	left, right := net.Pipe()
	client, err := smux.Client(left, nil)
	require.NoError(t, err)
	defer client.Close()
	server, err := smux.Server(right, nil)
	require.NoError(t, err)
	defer server.Close()
	stream, err := server.OpenStream()
	require.NoError(t, err)
	require.NoError(t, stream.SetDeadline(time.Now().Add(5*time.Second)))
	tc := &TunnelClient{codeServerMgr: m}
	go func() {
		incoming, err := client.AcceptStream()
		if err == nil {
			defer incoming.Close()
			tc.handleHealthCheck(incoming)
		}
	}()
	response, err := io.ReadAll(stream)
	require.NoError(t, err)
	assert.Contains(t, string(response), `"status":"error"`)
	assert.Contains(t, string(response), "code-server exited")

}

func TestCLIStreamRelaysMatchingSessionPort(t *testing.T) {
	dir, err := os.MkdirTemp("", "cli-relay-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "relay.sock")
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer ln.Close()
	require.NoError(t, ln.(*net.UnixListener).SetDeadline(time.Now().Add(5*time.Second)))
	tc := &TunnelClient{clientType: ClientTypeCLI, ctx: t.Context(), daemonSocket: socket}
	tc.targetPort.Store(8080)
	left, right := net.Pipe()
	client, err := smux.Client(left, nil)
	require.NoError(t, err)
	defer client.Close()
	server, err := smux.Server(right, nil)
	require.NoError(t, err)
	defer server.Close()
	stream, err := server.OpenStream()
	require.NoError(t, err)
	defer stream.Close()
	require.NoError(t, stream.SetDeadline(time.Now().Add(5*time.Second)))
	done := make(chan struct{})
	go func() {
		defer close(done)
		incoming, err := client.AcceptStream()
		if err == nil {
			tc.handleStream(incoming)
		}
	}()
	_, err = io.WriteString(stream, "{\"remote_port\":\"8080\"}\nrequest\n")
	require.NoError(t, err)
	conn, err := ln.Accept()
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	reader := bufio.NewReader(conn)
	target, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, net.JoinHostPort(loopbackHost, "8080")+"\n", target)
	request, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "request\n", request)
	_, err = io.WriteString(conn, "response\n")
	require.NoError(t, err)
	response, err := bufio.NewReader(stream).ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "response\n", response)
	require.NoError(t, stream.Close())
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish")
	}
}

func TestEditorSocketBaseNonRoot(t *testing.T) {
	if base := os.Getenv("ALPAMON_EDITOR_TEST_BASE"); base != "" {
		require.NotZero(t, os.Geteuid())
		require.NoError(t, ensureEditorSocketBase(base))
		info, err := os.Lstat(base)
		require.NoError(t, err)
		assert.Equal(t, uint32(os.Geteuid()), info.Sys().(*syscall.Stat_t).Uid)
		assert.Equal(t, os.FileMode(0711), info.Mode().Perm())
		for _, mode := range []os.FileMode{0770, 0707} {
			require.NoError(t, os.Chmod(base, mode))
			m := &CodeServerManager{socketPath: filepath.Join(base, "editor", "session", "cs.sock")}
			require.ErrorContains(t, prepareEditorSocketDir(m), "not writable by group or other")
		}
		require.NoError(t, os.Chmod(base, 0700))
		m := &CodeServerManager{socketPath: filepath.Join(base, "editor", "session", "cs.sock")}
		require.NoError(t, prepareEditorSocketDir(m))
		m.removeSocketDir()
		if other := os.Getenv("ALPAMON_EDITOR_OTHER_BASE"); other != "" {
			m := &CodeServerManager{socketPath: filepath.Join(other, "editor", "session", "cs.sock")}
			require.ErrorContains(t, prepareEditorSocketDir(m), "owned by the agent or root")
		}
		return
	}
	if os.Geteuid() != 0 {
		require.NoError(t, ensureEditorSocketBase(filepath.Join(t.TempDir(), "base")))
		return
	}
	dir, err := os.MkdirTemp("", "editor-uid-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	require.NoError(t, os.Chmod(dir, 0755))
	exe, err := os.Executable()
	require.NoError(t, err)
	data, err := os.ReadFile(exe)
	require.NoError(t, err)
	testBin := filepath.Join(dir, "runner.test")
	require.NoError(t, os.WriteFile(testBin, data, 0755))
	base := filepath.Join(dir, "base")
	require.NoError(t, os.Mkdir(base, 0700))
	uid, gid := lookupNobodyIDs(t)
	require.NoError(t, os.Chown(base, int(uid), int(gid)))
	cmd := exec.Command(testBin, "-test.run=^TestEditorSocketBaseNonRoot$")
	other := filepath.Join(dir, "other")
	require.NoError(t, os.Mkdir(other, 0755))
	require.NoError(t, os.Chown(other, 65533, 65533))
	cmd.Env = []string{"ALPAMON_EDITOR_TEST_BASE=" + base, "ALPAMON_EDITOR_OTHER_BASE=" + other}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", strings.TrimSpace(string(output)))
}

func TestEditorSocketProcessHelper(t *testing.T) {
	if os.Getenv("ALPAMON_EDITOR_SOCKET_HELPER") != "1" {
		return
	}
	var socket string
	for i, arg := range os.Args {
		if arg == "--socket" && i+1 < len(os.Args) {
			socket = os.Args[i+1]
		}
	}
	require.NotEmpty(t, socket)
	require.Equal(t, filepath.Dir(socket), os.Getenv("XDG_RUNTIME_DIR"))
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer listener.Close()
	for range 2 {
		conn, err := listener.Accept()
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	}
}

func TestEditorSweepContinuesAfterFailure(t *testing.T) {
	base := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(base, "failed"), 0700))
	require.NoError(t, os.Mkdir(filepath.Join(base, "leftover"), 0700))
	oldOnce, oldRemove, oldLog := editorSocketSweepOnce, removeEditorSocketEntry, log.Logger
	t.Cleanup(func() { editorSocketSweepOnce, removeEditorSocketEntry, log.Logger = oldOnce, oldRemove, oldLog })
	editorSocketSweepOnce = new(sync.Once)
	var output bytes.Buffer
	log.Logger = zerolog.New(&output)
	removeEditorSocketEntry = func(root *os.Root, name string) error {
		if name == "failed" {
			return os.ErrPermission
		}
		return root.RemoveAll(name)
	}
	require.NoError(t, ensureEditorSocketBase(base))
	require.NoError(t, ensureEditorSocketBase(base))
	_, err := os.Stat(filepath.Join(base, "leftover"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Contains(t, output.String(), `"level":"warn"`)
	assert.Contains(t, output.String(), "failed")
}

func TestEditorHealthUnavailableKeepsReady(t *testing.T) {
	m := &CodeServerManager{ctx: t.Context(), status: CodeServerStatusReady, socketPath: filepath.Join(t.TempDir(), "missing.sock")}
	left, right := net.Pipe()
	client, err := smux.Client(left, nil)
	require.NoError(t, err)
	defer client.Close()
	server, err := smux.Server(right, nil)
	require.NoError(t, err)
	defer server.Close()
	stream, err := server.OpenStream()
	require.NoError(t, err)
	require.NoError(t, stream.SetDeadline(time.Now().Add(5*time.Second)))
	tc := &TunnelClient{codeServerMgr: m}
	go func() {
		incoming, err := client.AcceptStream()
		if err == nil {
			defer incoming.Close()
			tc.handleHealthCheck(incoming)
		}
	}()
	response, err := io.ReadAll(stream)
	require.NoError(t, err)
	assert.Contains(t, string(response), "HTTP/1.1 503")
	assert.Contains(t, string(response), `"status":"starting"`)
	assert.NotContains(t, string(response), "code-server exited")
	status, message := m.Status()
	assert.Equal(t, CodeServerStatusReady, status)
	assert.Empty(t, message)
}

func TestEditorRunDirValidation(t *testing.T) {
	dir := t.TempDir()
	root, err := openEditorDirectory(dir)
	require.NoError(t, err)
	defer root.Close()
	for _, mode := range []os.FileMode{0770, 0707} {
		require.NoError(t, os.Chmod(dir, mode))
		require.ErrorContains(t, validateEditorRunDir(root, uint32(os.Geteuid())), "not writable by group or other")
	}
	require.NoError(t, os.Chmod(dir, 0700))
	require.NoError(t, validateEditorRunDir(root, uint32(os.Geteuid())))
	if os.Geteuid() != 0 {
		require.ErrorContains(t, validateEditorRunDir(root, uint32(os.Geteuid()+1)), "owned by the agent or root")
	}
}

func ensureEditorSocketBase(base string) error {
	root, err := openEditorSocketBase(base)
	if err != nil {
		return err
	}
	return root.Close()
}

func createEditorSessionDir(dir string, uid, gid int, chown func(string, int, int) error) error {
	root, err := openEditorDirectory(filepath.Dir(dir))
	if err != nil {
		return err
	}
	defer root.Close()
	return createEditorSessionDirAt(root, filepath.Base(dir), uid, gid, func(name string, uid, gid int) error { return chown(filepath.Join(filepath.Dir(dir), name), uid, gid) })
}

func sweepEditorSocketBase(base string) error {
	root, err := openEditorDirectory(base)
	if err != nil {
		return err
	}
	defer root.Close()
	sweepEditorSocketRoot(root)
	return nil
}

func prepareTestEditorSocketDir(m *CodeServerManager, uid, gid int, chown func(string, int, int) error) error {
	root, err := openEditorDirectory(filepath.Dir(filepath.Dir(m.socketPath)))
	if err != nil {
		return err
	}
	m.socketRoot = root
	return createEditorSessionDirAt(root, filepath.Base(filepath.Dir(m.socketPath)), uid, gid, func(name string, uid, gid int) error {
		return chown(filepath.Join(filepath.Dir(filepath.Dir(m.socketPath)), name), uid, gid)
	})
}

func TestEditorDirectoryReopenRejectsReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run")
	require.NoError(t, os.Mkdir(path, 0755))
	original := editorOpenRoot
	t.Cleanup(func() { editorOpenRoot = original })
	editorOpenRoot = func(name string) (*os.Root, error) {
		require.NoError(t, os.Rename(path, path+"-old"))
		require.NoError(t, os.Mkdir(path, 0755))
		return original(name)
	}
	root, err := openEditorDirectory(path)
	assert.ErrorContains(t, err, "changed while opening")
	assert.Nil(t, root)
}

func TestEditorSocketBaseReopenRejectsReplacement(t *testing.T) {
	path := t.TempDir()
	parent, err := os.OpenRoot(path)
	require.NoError(t, err)
	defer parent.Close()
	original := editorOpenRootAt
	t.Cleanup(func() { editorOpenRootAt = original })
	editorOpenRootAt = func(parent *os.Root, name string) (*os.Root, error) {
		require.NoError(t, os.Rename(filepath.Join(path, name), filepath.Join(path, name+"-old")))
		require.NoError(t, parent.Mkdir(name, 0711))
		return original(parent, name)
	}
	root, err := openEditorSocketBaseAt(parent, "editor")
	assert.ErrorContains(t, err, "changed while opening")
	assert.Nil(t, root)
}

func TestEditorSocketAcceptsRequestedPeerUID(t *testing.T) {
	dir, err := os.MkdirTemp("", "editor-peer-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "cs.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer listener.Close()
	m := &CodeServerManager{ctx: t.Context(), socketPath: socket, procAttr: &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(os.Geteuid()), Gid: uint32(os.Getegid())}}}
	conn, err := m.dialSocket()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
}

func TestEditorSocketBaseAllowsParentSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "private-run")
	require.NoError(t, os.Mkdir(target, 0755))
	link := filepath.Join(dir, "run")
	require.NoError(t, os.Symlink(target, link))
	root, err := openEditorSocketBase(filepath.Join(link, "editor"))
	require.NoError(t, err)
	defer root.Close()
	pinned, err := root.Stat(".")
	require.NoError(t, err)
	actual, err := os.Stat(filepath.Join(target, "editor"))
	require.NoError(t, err)
	assert.True(t, os.SameFile(pinned, actual))
}
