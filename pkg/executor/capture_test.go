package executor

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCapBuffer_KeepsSmallStreamWhole(t *testing.T) {
	c := newCapBuffer()
	c.write([]byte("hello world"))

	assert.Equal(t, "hello world", string(c.bytes()))
}

func TestCapBuffer_TruncatesMiddleKeepingEnds(t *testing.T) {
	c := newCapBuffer()

	head := bytes.Repeat([]byte("A"), captureHeadCap)
	mid := bytes.Repeat([]byte("B"), 100000)
	tail := bytes.Repeat([]byte("C"), captureTailCap)
	c.write(head)
	c.write(mid)
	c.write(tail)

	got := c.bytes()

	assert.True(t, bytes.HasPrefix(got, head), "output should keep the first %d bytes", captureHeadCap)
	assert.True(t, bytes.HasSuffix(got, tail), "output should keep the last %d bytes", captureTailCap)
	assert.Contains(t, string(got), "100000 bytes truncated", "output should mark the dropped middle, got %q", truncatedMarkerOf(got))
	// Bounded: head + tail + a short marker.
	assert.LessOrEqual(t, len(got), captureCap+64, "output size exceeds cap+marker")
}

func truncatedMarkerOf(b []byte) string {
	i := bytes.Index(b, []byte("\n..."))
	if i < 0 {
		return ""
	}
	return string(b[i : i+40])
}

// Blocks exceed captureTailCap so in-write compaction fires; only the last tail bytes survive.
func TestCapBuffer_CompactsAcrossWrites(t *testing.T) {
	c := newCapBuffer()

	block := bytes.Repeat([]byte("x"), captureTailCap+1000)
	var total int
	for range 5 {
		c.write(block)
		total += len(block)
	}

	got := c.bytes()
	require.LessOrEqual(t, len(got), captureCap+64, "output size exceeds cap+marker")
	dropped := total - captureCap
	want := fmt.Sprintf("%d bytes truncated", dropped)
	require.Contains(t, string(got), want, "expected marker %q, got %q", want, truncatedMarkerOf(got))
}
