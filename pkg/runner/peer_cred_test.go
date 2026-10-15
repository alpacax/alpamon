package runner

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPeerUIDAllowed_AcceptsRootAndSelfOnly(t *testing.T) {
	cases := []struct {
		name     string
		uid      int
		selfEUID int
		want     bool
	}{
		{"root peer, root agent", 0, 0, true},
		{"root peer, user agent", 0, 1000, true},
		{"same user as agent", 1000, 1000, true},
		{"other user, root agent", 1000, 0, false},
		{"other user, user agent", 1001, 1000, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, peerUIDAllowed(tc.uid, tc.selfEUID))
		})
	}
}

func TestPeerCredentials_RejectsNonUnixConnection(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	_, err := peerCredentials(server)

	assert.Error(t, err)
}
