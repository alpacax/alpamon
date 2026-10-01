package executor

import (
	"context"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Batching contract: newlines don't emit; output emits on the size threshold, a flush tick, or final flush.

func TestChunkWriter_BuffersUntilFlush(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(context.Background(), func(_ context.Context, content string) { chunks = append(chunks, content) })

	_, err := cw.Write([]byte("line1\n"))
	require.NoError(t, err, "write")
	_, err = cw.Write([]byte("line2\n"))
	require.NoError(t, err, "write")
	require.Empty(t, chunks, "newlines must not emit")

	cw.flush()
	assert.Equal(t, []string{"line1\nline2\n"}, chunks, "flush should coalesce buffered writes")
}

func TestChunkWriter_CoalescesMultipleWrites(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(context.Background(), func(_ context.Context, content string) { chunks = append(chunks, content) })

	for _, s := range []string{"a\n", "b\n", "c\n"} {
		_, err := cw.Write([]byte(s))
		require.NoError(t, err, "write")
	}
	require.Empty(t, chunks, "expected no chunks before flush")

	cw.flush()
	assert.Equal(t, []string{"a\nb\nc\n"}, chunks, "flush should emit one coalesced chunk")
}

func TestChunkWriter_PartialLineCarriedOver(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(context.Background(), func(_ context.Context, content string) { chunks = append(chunks, content) })

	_, err := cw.Write([]byte("hello"))
	require.NoError(t, err, "write")
	_, err = cw.Write([]byte(" world\n"))
	require.NoError(t, err, "write")
	require.Empty(t, chunks, "expected no chunks before flush")

	cw.flush()
	assert.Equal(t, []string{"hello world\n"}, chunks, "expected concatenated line")
}

func TestChunkWriter_FlushEmitsRemainder(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(context.Background(), func(_ context.Context, content string) { chunks = append(chunks, content) })

	_, err := cw.Write([]byte("no newline"))
	require.NoError(t, err, "write")
	require.Empty(t, chunks, "expected no chunks before flush")

	cw.flush()
	assert.Equal(t, []string{"no newline"}, chunks, "flush should emit remainder")

	// Second flush is a no-op.
	cw.flush()
	assert.Len(t, chunks, 1, "second flush should be no-op")
}

func TestChunkWriter_ThresholdTriggersEmissionWithoutNewline(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(context.Background(), func(_ context.Context, content string) { chunks = append(chunks, content) })

	big := strings.Repeat("x", chunkSizeThreshold+10)
	_, err := cw.Write([]byte(big))
	require.NoError(t, err, "write")

	// First 4KB emits; sub-threshold tail stays buffered until Flush.
	require.Len(t, chunks, 1, "threshold should trigger one emission")
	assert.Equal(t, strings.Repeat("x", chunkSizeThreshold), chunks[0], "emitted chunk should be exactly chunkSizeThreshold bytes")

	cw.flush()
	assert.Equal(t, []string{strings.Repeat("x", chunkSizeThreshold), strings.Repeat("x", 10)}, chunks, "flush should emit 10-byte tail")
}

func TestChunkWriter_RecoversFromCallbackPanic(t *testing.T) {
	var calls int
	cw := newChunkWriter(context.Background(), func(_ context.Context, content string) {
		calls++
		if calls == 1 {
			panic("boom")
		}
	})

	// Each threshold-sized write forces one emit; the first panics.
	block := strings.Repeat("x", chunkSizeThreshold)
	_, err := cw.Write([]byte(block))
	require.NoError(t, err, "write")
	_, err = cw.Write([]byte(block))
	require.NoError(t, err, "write")
	_, err = cw.Write([]byte("tail"))
	require.NoError(t, err, "write")
	cw.flush()

	assert.Equal(t, 3, calls, "expected 3 callback invocations after recovery")
}

func chunkSizes(chunks []string) []int {
	sizes := make([]int, len(chunks))
	for i, c := range chunks {
		sizes[i] = len(c)
	}
	return sizes
}

func TestChunkWriter_WriteReturnsFullLength(t *testing.T) {
	cw := newChunkWriter(context.Background(), func(_ context.Context, content string) {})

	in := []byte("partial")
	n, err := cw.Write(in)
	require.NoError(t, err, "write")
	assert.Equal(t, len(in), n, "Write should return full length")
}

// Regression: a buffer crossing the threshold emits an exact threshold chunk
// first and never a single oversized payload, even when the crossing write
// ends in a newline.
func TestChunkWriter_OversizedBufferSplitsAtThreshold(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(context.Background(), func(_ context.Context, content string) { chunks = append(chunks, content) })

	tail := strings.Repeat("a", chunkSizeThreshold-100)
	_, err := cw.Write([]byte(tail))
	require.NoError(t, err, "write tail")
	require.Empty(t, chunks, "expected no chunks yet")

	_, err = cw.Write([]byte(strings.Repeat("b", 199) + "\n"))
	require.NoError(t, err, "write line end")

	require.Len(t, chunks, 1, "expected 1 threshold chunk before flush, sizes %v", chunkSizes(chunks))
	assert.Len(t, chunks[0], chunkSizeThreshold, "chunk[0] size")

	cw.flush()
	require.Len(t, chunks, 2, "flush should emit the 100-byte tail, sizes %v", chunkSizes(chunks))
	require.Len(t, chunks[1], 100, "flush should emit the 100-byte tail")
	assert.True(t, strings.HasSuffix(chunks[1], "\n"), "final chunk should retain trailing newline, got %q", chunks[1])
}

// Regression: chunks stream every byte while the audit capture stays bounded.
func TestChunkWriter_StreamsAllWithBoundedCapture(t *testing.T) {
	emitted := 0
	cw := newChunkWriter(context.Background(), func(_ context.Context, content string) { emitted += len(content) })

	block := strings.Repeat("z", 256*1024)
	const writes = 6
	for i := range writes {
		_, err := cw.Write([]byte(block))
		require.NoError(t, err, "write %d", i)
	}
	cw.flush()

	assert.Equal(t, len(block)*writes, emitted, "emitted bytes")
	assert.Zero(t, cw.buf.Len(), "emit buffer should be empty after flush")
	assert.LessOrEqual(t, len(cw.captured()), captureCap+64, "capture size exceeds cap+marker")
}

// The flusher goroutine emits sub-threshold buffered output within the
// interval, so slow line-rate commands still stream without waiting for close.
func TestChunkWriter_FlusherEmitsBufferedOutput(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var chunks []string
		cw := newChunkWriter(context.Background(), func(_ context.Context, content string) {
			mu.Lock()
			defer mu.Unlock()
			chunks = append(chunks, content)
		})

		cw.start(5 * time.Millisecond)
		defer cw.close()

		_, err := cw.Write([]byte("partial"))
		require.NoError(t, err, "write")

		time.Sleep(5 * time.Millisecond)
		synctest.Wait()

		mu.Lock()
		defer mu.Unlock()
		require.NotEmpty(t, chunks, "flusher did not emit buffered output")
		assert.Equal(t, "partial", chunks[0])
	})
}

// A multi-byte rune straddling the 4KB cut must not be split—a split chunk is invalid UTF-8.
func TestChunkWriter_DoesNotSplitRuneAtThreshold(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(context.Background(), func(_ context.Context, content string) { chunks = append(chunks, content) })

	// '가' (3 bytes) starts at chunkSizeThreshold-2 so its 3rd byte lands past the
	// cut; trailing 'b's keep buf over threshold so the Write loop emits before flush.
	input := strings.Repeat("a", chunkSizeThreshold-2) + "가" + strings.Repeat("b", chunkSizeThreshold)
	_, err := cw.Write([]byte(input))
	require.NoError(t, err, "write")
	cw.flush()

	for i, c := range chunks {
		assert.True(t, utf8.ValidString(c), "chunk %d is not valid UTF-8—a rune was split at the boundary", i)
	}
	assert.Equal(t, input, strings.Join(chunks, ""), "reassembled output mismatch")
}
