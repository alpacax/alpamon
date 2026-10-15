//go:build !windows

package runner

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dialAuthSocket returns a client end and the agent end of a real Unix socket,
// so SO_PEERCRED/LOCAL_PEERCRED see this test process as the peer.
func dialAuthSocket(t *testing.T) (client net.Conn, server net.Conn) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "as") // t.TempDir() overflows sun_path on macOS.
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, err := utils.ListenUnixPrivate(filepath.Join(dir, "auth.sock"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	client, err = net.Dial("unix", filepath.Join(dir, "auth.sock"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	server, err = ln.Accept()
	require.NoError(t, err)
	return client, server
}

func sendCheckUser(t *testing.T, client net.Conn, pid int) {
	t.Helper()
	req, err := json.Marshal(map[string]any{"type": "check_user", "username": "alice", "groupname": "alice", "pid": pid, "ppid": 1})
	require.NoError(t, err)
	_, err = client.Write(req)
	require.NoError(t, err)
}

func TestHandleSudoRequest_AnswersRequestFromTheConnectingProcess(t *testing.T) {
	am := newTestAuthManager()
	am.peerCreds = peerCredentials
	client, server := dialAuthSocket(t)
	sendCheckUser(t, client, os.Getpid())

	am.handleSudoRequest(server)

	body, err := io.ReadAll(client)
	require.NoError(t, err)
	var resp IsAlpconResponse
	require.NoError(t, json.Unmarshal(body, &resp))
	assert.Equal(t, "is_alpacon_response", resp.Type)
}

func TestHandleSudoRequest_DropsConnectionWhenPeerCheckIsNotConfigured(t *testing.T) {
	am := NewEmptyAuthManager()
	client, server := dialAuthSocket(t)
	sendCheckUser(t, client, os.Getpid())

	am.handleSudoRequest(server)

	body, err := io.ReadAll(client)
	if err != nil {
		require.ErrorIs(t, err, syscall.ECONNRESET) // Linux resets a socket closed with its request still unread.
	}
	assert.Empty(t, body, "a request was answered without a peer check")
}
