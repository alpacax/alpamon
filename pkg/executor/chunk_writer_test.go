package executor

import (
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// Batching contract: newlines don't emit; output emits on the size threshold, a flush tick, or final flush.

func TestChunkWriter_BuffersUntilFlush(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(func(content string) { chunks = append(chunks, content) })

	if _, err := cw.Write([]byte("line1\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := cw.Write([]byte("line2\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(chunks) != 0 {
		t.Fatalf("newlines must not emit; got %v", chunks)
	}

	cw.flush()
	if len(chunks) != 1 || chunks[0] != "line1\nline2\n" {
		t.Errorf("flush should coalesce buffered writes, got %v", chunks)
	}
}

func TestChunkWriter_CoalescesMultipleWrites(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(func(content string) { chunks = append(chunks, content) })

	for _, s := range []string{"a\n", "b\n", "c\n"} {
		if _, err := cw.Write([]byte(s)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if len(chunks) != 0 {
		t.Fatalf("expected no chunks before flush, got %v", chunks)
	}

	cw.flush()
	if len(chunks) != 1 || chunks[0] != "a\nb\nc\n" {
		t.Errorf("flush should emit one coalesced chunk, got %v", chunks)
	}
}

func TestChunkWriter_PartialLineCarriedOver(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(func(content string) { chunks = append(chunks, content) })

	if _, err := cw.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := cw.Write([]byte(" world\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(chunks) != 0 {
		t.Fatalf("expected no chunks before flush, got %v", chunks)
	}

	cw.flush()
	if len(chunks) != 1 || chunks[0] != "hello world\n" {
		t.Errorf("expected concatenated line, got %v", chunks)
	}
}

func TestChunkWriter_FlushEmitsRemainder(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(func(content string) { chunks = append(chunks, content) })

	if _, err := cw.Write([]byte("no newline")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(chunks) != 0 {
		t.Fatalf("expected no chunks before flush, got %v", chunks)
	}

	cw.flush()
	if len(chunks) != 1 || chunks[0] != "no newline" {
		t.Errorf("flush should emit remainder, got %v", chunks)
	}

	// Second flush is a no-op.
	cw.flush()
	if len(chunks) != 1 {
		t.Errorf("second flush should be no-op, got %v", chunks)
	}
}

func TestChunkWriter_ThresholdTriggersEmissionWithoutNewline(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(func(content string) { chunks = append(chunks, content) })

	big := strings.Repeat("x", chunkSizeThreshold+10)
	if _, err := cw.Write([]byte(big)); err != nil {
		t.Fatalf("write: %v", err)
	}

	// First 4KB emits; sub-threshold tail stays buffered until Flush.
	if len(chunks) != 1 {
		t.Fatalf("threshold should trigger one emission, got %d chunks", len(chunks))
	}
	if chunks[0] != strings.Repeat("x", chunkSizeThreshold) {
		t.Errorf("emitted chunk should be exactly chunkSizeThreshold bytes")
	}

	cw.flush()
	if len(chunks) != 2 || chunks[1] != strings.Repeat("x", 10) {
		t.Errorf("flush should emit 10-byte tail, got %v", chunks)
	}
}

func TestChunkWriter_RecoversFromCallbackPanic(t *testing.T) {
	var calls int
	cw := newChunkWriter(func(content string) {
		calls++
		if calls == 1 {
			panic("boom")
		}
	})

	// Each threshold-sized write forces one emit; the first panics.
	block := strings.Repeat("x", chunkSizeThreshold)
	if _, err := cw.Write([]byte(block)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := cw.Write([]byte(block)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := cw.Write([]byte("tail")); err != nil {
		t.Fatalf("write: %v", err)
	}
	cw.flush()

	if calls != 3 {
		t.Errorf("expected 3 callback invocations after recovery, got %d", calls)
	}
}

func chunkSizes(chunks []string) []int {
	sizes := make([]int, len(chunks))
	for i, c := range chunks {
		sizes[i] = len(c)
	}
	return sizes
}

func TestChunkWriter_WriteReturnsFullLength(t *testing.T) {
	cw := newChunkWriter(func(content string) {})

	in := []byte("partial")
	n, err := cw.Write(in)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(in) {
		t.Errorf("Write should return full length: got %d, want %d", n, len(in))
	}
}

// Regression: a buffer crossing the threshold emits an exact threshold chunk
// first and never a single oversized payload, even when the crossing write
// ends in a newline.
func TestChunkWriter_OversizedBufferSplitsAtThreshold(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(func(content string) { chunks = append(chunks, content) })

	tail := strings.Repeat("a", chunkSizeThreshold-100)
	if _, err := cw.Write([]byte(tail)); err != nil {
		t.Fatalf("write tail: %v", err)
	}
	if len(chunks) != 0 {
		t.Fatalf("expected no chunks yet, got %d", len(chunks))
	}

	if _, err := cw.Write([]byte(strings.Repeat("b", 199) + "\n")); err != nil {
		t.Fatalf("write line end: %v", err)
	}

	if len(chunks) != 1 {
		t.Fatalf("expected 1 threshold chunk before flush, got %d (%v)", len(chunks), chunkSizes(chunks))
	}
	if len(chunks[0]) != chunkSizeThreshold {
		t.Errorf("chunk[0] size: got %d, want %d", len(chunks[0]), chunkSizeThreshold)
	}

	cw.flush()
	if len(chunks) != 2 || len(chunks[1]) != 100 {
		t.Fatalf("flush should emit the 100-byte tail, got %v", chunkSizes(chunks))
	}
	if !strings.HasSuffix(chunks[1], "\n") {
		t.Errorf("final chunk should retain trailing newline, got %q", chunks[1])
	}
}

// Regression: chunks stream every byte while the audit capture stays bounded.
func TestChunkWriter_StreamsAllWithBoundedCapture(t *testing.T) {
	emitted := 0
	cw := newChunkWriter(func(content string) { emitted += len(content) })

	block := strings.Repeat("z", 256*1024)
	const writes = 6
	for i := range writes {
		if _, err := cw.Write([]byte(block)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	cw.flush()

	if want := len(block) * writes; emitted != want {
		t.Errorf("emitted bytes: got %d, want %d", emitted, want)
	}
	if cw.buf.Len() != 0 {
		t.Errorf("emit buffer should be empty after flush, has %d bytes", cw.buf.Len())
	}
	if got := len(cw.captured()); got > captureCap+64 {
		t.Errorf("capture size %d exceeds cap+marker", got)
	}
}

// The flusher goroutine emits sub-threshold buffered output within the
// interval, so slow line-rate commands still stream without waiting for close.
func TestChunkWriter_FlusherEmitsBufferedOutput(t *testing.T) {
	var mu sync.Mutex
	var chunks []string
	cw := newChunkWriter(func(content string) {
		mu.Lock()
		defer mu.Unlock()
		chunks = append(chunks, content)
	})

	cw.start(5 * time.Millisecond)
	defer cw.close()

	if _, err := cw.Write([]byte("partial")); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(chunks)
		mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("flusher did not emit buffered output within deadline")
		}
		time.Sleep(2 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if chunks[0] != "partial" {
		t.Errorf("flusher emitted %q, want %q", chunks[0], "partial")
	}
}

// A multi-byte rune straddling the 4KB cut must not be split—a split chunk is invalid UTF-8.
func TestChunkWriter_DoesNotSplitRuneAtThreshold(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(func(content string) { chunks = append(chunks, content) })

	// '가' (3 bytes) starts at chunkSizeThreshold-2 so its 3rd byte lands past the
	// cut; trailing 'b's keep buf over threshold so the Write loop emits before flush.
	input := strings.Repeat("a", chunkSizeThreshold-2) + "가" + strings.Repeat("b", chunkSizeThreshold)
	if _, err := cw.Write([]byte(input)); err != nil {
		t.Fatalf("write: %v", err)
	}
	cw.flush()

	for i, c := range chunks {
		if !utf8.ValidString(c) {
			t.Errorf("chunk %d is not valid UTF-8—a rune was split at the boundary", i)
		}
	}
	if got := strings.Join(chunks, ""); got != input {
		t.Errorf("reassembled output mismatch: got %d bytes, want %d", len(got), len(input))
	}
}
