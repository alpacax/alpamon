package executor

import (
	"bytes"
	"fmt"
	"slices"
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
	assert.True(t, bytes.Contains(got, []byte("100000 bytes truncated")), "output should mark the dropped middle, got %q", truncatedMarkerOf(got))
	// Bounded: head + tail + a short marker.
	assert.LessOrEqual(t, len(got), captureCap+64, "output size exceeds cap+marker")
}

func truncatedMarkerOf(b []byte) string {
	i := bytes.Index(b, []byte("\n..."))
	if i < 0 {
		return ""
	}
	return string(b[i:min(i+40, len(b))])
}

// Blocks stay under captureTailCap so the tail outgrows 2x and compacts in place.
func TestCapBuffer_CompactsAcrossWrites(t *testing.T) {
	c := newCapBuffer()

	block := bytes.Repeat([]byte("x"), captureTailCap/2+1000)
	var total int
	for range 8 {
		c.write(block)
		total += len(block)
	}

	got := c.bytes()
	require.LessOrEqual(t, len(got), captureCap+64, "output size exceeds cap+marker")
	dropped := total - captureCap
	want := fmt.Sprintf("%d bytes truncated", dropped)
	require.True(t, bytes.Contains(got, []byte(want)), "expected marker %q, got %q", want, truncatedMarkerOf(got))
}

func patternStream(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*7 + i>>8)
	}
	return out
}

func wantCapped(stream []byte) []byte {
	if len(stream) <= captureCap {
		return stream
	}
	marker := fmt.Sprintf("\n... [%d bytes truncated] ...\n", len(stream)-captureCap)
	return slices.Concat(stream[:captureHeadCap], []byte(marker), stream[len(stream)-captureTailCap:])
}

func TestCapBuffer_KeepsHeadAndLastTailAcrossManyCompactions(t *testing.T) {
	stream := patternStream(captureHeadCap + 7*captureTailCap + 123)
	c := newCapBuffer()

	for chunk := range slices.Chunk(stream, 64) {
		c.write(chunk)
	}

	require.Equal(t, wantCapped(stream), c.bytes())
}

func TestCapBuffer_MatchesCappedStreamAtBoundaries(t *testing.T) {
	sizes := []int{
		captureHeadCap, captureCap, captureCap + 1,
		captureHeadCap + 2*captureTailCap, captureHeadCap + 2*captureTailCap + 1,
		captureHeadCap + 2*captureTailCap + 2,
	}
	for _, size := range sizes {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			stream := patternStream(size)
			c := newCapBuffer()

			c.write(stream[:size/3])
			c.write(stream[size/3:])

			assert.Equal(t, wantCapped(stream), c.bytes())
		})
	}
}

func TestCapBuffer_BytesIsRepeatableAndWritableAfterwards(t *testing.T) {
	stream := patternStream(captureHeadCap + 3*captureTailCap)
	extra := patternStream(captureTailCap + 5)
	c := newCapBuffer()
	c.write(stream)

	first := c.bytes()
	second := c.bytes()
	c.write(extra)

	assert.Equal(t, first, second)
	assert.Equal(t, wantCapped(slices.Concat(stream, extra)), c.bytes())
}

func TestCapBuffer_OversizedWriteDoesNotRetainItsBackingArray(t *testing.T) {
	stream := patternStream(captureHeadCap + 64*captureTailCap)
	c := newCapBuffer()

	c.write(stream)

	assert.LessOrEqual(t, cap(c.tail), 4*captureTailCap, "tail keeps the oversized write's allocation")
	assert.Equal(t, wantCapped(stream), c.bytes())
}
