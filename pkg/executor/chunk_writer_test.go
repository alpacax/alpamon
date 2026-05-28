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

	if len(chunks) != 1 {
		t.Fatalf("threshold should trigger emission, got %d chunks", len(chunks))
	}
	if chunks[0] != big {
		t.Errorf("emitted chunk does not match input")
	}
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

func TestChunkWriter_BytesReturnsFullOutput(t *testing.T) {
	cw := newChunkWriter(func(content string) {})

	inputs := []string{"hello\n", "world", "!\n"}
	for _, s := range inputs {
		if _, err := cw.Write([]byte(s)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	cw.Flush()

	got := string(cw.Bytes())
	want := "hello\nworld!\n"
	if got != want {
		t.Errorf("Bytes(): got %q, want %q", got, want)
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
