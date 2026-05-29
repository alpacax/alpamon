package executor

import (
	"strings"
	"testing"
)

func TestChunkWriter_EmitsOnNewline(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(func(content string) { chunks = append(chunks, content) })

	if _, err := cw.Write([]byte("line1\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := cw.Write([]byte("line2\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got, want := len(chunks), 2; got != want {
		t.Fatalf("chunks: got %d, want %d (%v)", got, want, chunks)
	}
	if chunks[0] != "line1\n" || chunks[1] != "line2\n" {
		t.Errorf("unexpected chunks: %v", chunks)
	}
}

func TestChunkWriter_MultipleLinesInSingleWrite(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(func(content string) { chunks = append(chunks, content) })

	if _, err := cw.Write([]byte("a\nb\nc\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	want := []string{"a\n", "b\n", "c\n"}
	if len(chunks) != len(want) {
		t.Fatalf("chunks: got %d, want %d (%v)", len(chunks), len(want), chunks)
	}
	for i, c := range chunks {
		if c != want[i] {
			t.Errorf("chunk[%d]: got %q, want %q", i, c, want[i])
		}
	}
}

func TestChunkWriter_PartialLineCarriedOver(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(func(content string) { chunks = append(chunks, content) })

	if _, err := cw.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(chunks) != 0 {
		t.Fatalf("expected no chunks yet, got %v", chunks)
	}

	if _, err := cw.Write([]byte(" world\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
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

	cw.Flush()
	if len(chunks) != 1 || chunks[0] != "no newline" {
		t.Errorf("flush should emit remainder, got %v", chunks)
	}

	// Second flush is a no-op.
	cw.Flush()
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

	cw.Flush()
	if len(chunks) != 2 || chunks[1] != strings.Repeat("x", 10) {
		t.Errorf("flush should emit 10-byte tail, got %v", chunks)
	}
}

func TestChunkWriter_LongSingleLineSplitsIntoFixedChunks(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(func(content string) { chunks = append(chunks, content) })

	big := strings.Repeat("y", chunkSizeThreshold*3+50)
	if _, err := cw.Write([]byte(big)); err != nil {
		t.Fatalf("write: %v", err)
	}

	if len(chunks) != 3 {
		t.Fatalf("expected 3 fixed-size chunks before flush, got %d", len(chunks))
	}
	for i, c := range chunks {
		if len(c) != chunkSizeThreshold {
			t.Errorf("chunk[%d] size: got %d, want %d", i, len(c), chunkSizeThreshold)
		}
	}

	cw.Flush()
	if len(chunks) != 4 || len(chunks[3]) != 50 {
		t.Errorf("flush should emit 50-byte tail, got %d chunks with sizes %v",
			len(chunks), chunkSizes(chunks))
	}

	if assembled := strings.Join(chunks, ""); assembled != big {
		t.Error("assembled chunks should reproduce the full input")
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

	if _, err := cw.Write([]byte("first\nsecond\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := cw.Write([]byte("tail")); err != nil {
		t.Fatalf("write: %v", err)
	}
	cw.Flush()

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

func TestChunkWriter_MixedLinesAndTail(t *testing.T) {
	var chunks []string
	cw := newChunkWriter(func(content string) { chunks = append(chunks, content) })

	if _, err := cw.Write([]byte("line1\nline2\nincomplete")); err != nil {
		t.Fatalf("write: %v", err)
	}

	if len(chunks) != 2 {
		t.Fatalf("expected 2 line chunks before flush, got %v", chunks)
	}
	if chunks[0] != "line1\n" || chunks[1] != "line2\n" {
		t.Errorf("unexpected line chunks: %v", chunks)
	}

	cw.Flush()
	if len(chunks) != 3 || chunks[2] != "incomplete" {
		t.Errorf("flush should append tail, got %v", chunks)
	}
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

// Regression: buffered tail + next Write must not emit payload > threshold.
func TestChunkWriter_NewlineLineExceedingThresholdSplits(t *testing.T) {
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

	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks after split, got %d (%v)", len(chunks), chunkSizes(chunks))
	}
	if len(chunks[0]) != chunkSizeThreshold {
		t.Errorf("chunk[0] size: got %d, want %d", len(chunks[0]), chunkSizeThreshold)
	}
	if len(chunks[1]) != (chunkSizeThreshold-100)+200-chunkSizeThreshold {
		t.Errorf("chunk[1] size: got %d, want 100", len(chunks[1]))
	}
	if !strings.HasSuffix(chunks[1], "\n") {
		t.Errorf("final chunk should retain trailing newline, got %q", chunks[1])
	}
}

// Regression: writer must not retain unbounded memory across large writes.
func TestChunkWriter_LargeStreamDoesNotRetainBody(t *testing.T) {
	emitted := 0
	cw := newChunkWriter(func(content string) { emitted += len(content) })

	block := strings.Repeat("z", 256*1024)
	const writes = 6
	for i := 0; i < writes; i++ {
		if _, err := cw.Write([]byte(block)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	cw.Flush()

	if want := len(block) * writes; emitted != want {
		t.Errorf("emitted bytes: got %d, want %d", emitted, want)
	}
	if cw.buf.Len() != 0 {
		t.Errorf("buf should be empty after flush, has %d bytes", cw.buf.Len())
	}
}
