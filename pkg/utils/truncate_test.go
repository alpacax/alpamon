package utils

import (
	"strings"
	"testing"
)

func TestTruncateMiddle_ShortStringUnchanged(t *testing.T) {
	if got := TruncateMiddle("hello", 100); got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestTruncateMiddle_AtLimitUnchanged(t *testing.T) {
	s := strings.Repeat("a", 100)
	if got := TruncateMiddle(s, 100); got != s {
		t.Errorf("string at the limit must be unchanged")
	}
}

func TestTruncateMiddle_KeepsEndsDropsMiddle(t *testing.T) {
	head := strings.Repeat("A", 50)
	mid := strings.Repeat("B", 200)
	tail := strings.Repeat("C", 50)
	got := TruncateMiddle(head+mid+tail, 100)

	if !strings.HasPrefix(got, strings.Repeat("A", 50)) {
		t.Errorf("should keep the first 50 bytes")
	}
	if !strings.HasSuffix(got, strings.Repeat("C", 50)) {
		t.Errorf("should keep the last 50 bytes")
	}
	if !strings.Contains(got, "200 bytes truncated") {
		t.Errorf("should report the exact dropped count, got %q", got)
	}
}
