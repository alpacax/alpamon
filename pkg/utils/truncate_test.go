package utils

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncateMiddle_ShortStringUnchanged(t *testing.T) {
	assert.Equal(t, "hello", TruncateMiddle("hello", 100))
}

func TestTruncateMiddle_AtLimitUnchanged(t *testing.T) {
	s := strings.Repeat("a", 100)
	assert.Equal(t, s, TruncateMiddle(s, 100), "string at the limit must be unchanged")
}

func TestTruncateMiddle_KeepsEndsDropsMiddle(t *testing.T) {
	head := strings.Repeat("A", 50)
	mid := strings.Repeat("B", 200)
	tail := strings.Repeat("C", 50)
	got := TruncateMiddle(head+mid+tail, 100)

	assert.True(t, strings.HasPrefix(got, strings.Repeat("A", 50)), "should keep the first 50 bytes")
	assert.True(t, strings.HasSuffix(got, strings.Repeat("C", 50)), "should keep the last 50 bytes")
	assert.Contains(t, got, "200 bytes truncated", "should report the exact dropped count")
}
