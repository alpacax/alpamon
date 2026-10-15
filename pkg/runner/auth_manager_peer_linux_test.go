//go:build linux

package runner

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleSudoRequest_DropsRequestClaimingAnotherPID(t *testing.T) {
	am := newTestAuthManager()
	am.peerCreds = peerCredentials
	client, server := dialAuthSocket(t)
	sendCheckUser(t, client, os.Getpid()+1)

	am.handleSudoRequest(server)

	body, err := io.ReadAll(client)
	require.NoError(t, err)
	assert.Empty(t, body, "a request with a spoofed pid was answered")
}

func TestHandleSudoRequest_DropsRequestWithoutPID(t *testing.T) {
	am := newTestAuthManager()
	am.peerCreds = peerCredentials
	client, server := dialAuthSocket(t)
	_, err := client.Write([]byte(`{"type":"check_user","username":"alice"}`))
	require.NoError(t, err)

	am.handleSudoRequest(server)

	body, err := io.ReadAll(client)
	require.NoError(t, err)
	assert.Empty(t, body, "a request without a pid was answered")
}

func TestPeerCredentials_ReportsThisProcessOnLinux(t *testing.T) {
	_, server := dialAuthSocket(t)

	peer, err := peerCredentials(server)

	require.NoError(t, err)
	assert.True(t, peer.pidKnown)
	assert.Equal(t, os.Getpid(), peer.pid)
	assert.Equal(t, os.Geteuid(), peer.uid)
}
