package executor

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestCapBuffer_KeepsSmallStreamWhole(t *testing.T) {
	c := newCapBuffer()
	c.write([]byte("hello world"))

	if got := string(c.bytes()); got != "hello world" {
		t.Errorf("got %q, want %q", got, "hello world")
	}
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

	if !bytes.HasPrefix(got, head) {
		t.Errorf("output should keep the first %d bytes", captureHeadCap)
	}
	if !bytes.HasSuffix(got, tail) {
		t.Errorf("output should keep the last %d bytes", captureTailCap)
	}
	if !strings.Contains(string(got), "100000 bytes truncated") {
		t.Errorf("output should mark the dropped middle, got %q", truncatedMarkerOf(got))
	}
	// Bounded: head + tail + a short marker.
	if len(got) > captureCap+64 {
		t.Errorf("output size %d exceeds cap+marker", len(got))
	}
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
	for i := 0; i < 5; i++ {
		c.write(block)
		total += len(block)
	}

	got := c.bytes()
	if len(got) > captureCap+64 {
		t.Fatalf("output size %d exceeds cap+marker", len(got))
	}
	dropped := total - captureCap
	if want := fmt.Sprintf("%d bytes truncated", dropped); !strings.Contains(string(got), want) {
		t.Fatalf("expected marker %q, got %q", want, truncatedMarkerOf(got))
	}
}
