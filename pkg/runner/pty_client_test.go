//go:build !windows

package runner

import (
	"testing"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/stretchr/testify/assert"
)

func TestNewPtyClientChannelsUseChannelCapacity(t *testing.T) {
	pc := NewPtyClient(protocol.CommandData{}, nil, nil)

	assert.Equal(t, channelCapacity, cap(pc.ptyToWs))
	assert.Equal(t, channelCapacity, cap(pc.wsToPty))
}

func BenchmarkNewPtyClient(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NewPtyClient(protocol.CommandData{}, nil, nil)
	}
}
