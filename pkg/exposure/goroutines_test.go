package exposure

import (
	"bytes"
	"regexp"
	"runtime"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
)

var bubbleHeader = regexp.MustCompile(`(?m)^goroutine \d+ \[[^\n]*, synctest bubble (\d+)\b`)

// bubbleGoroutines counts the goroutines in the caller's synctest bubble; runtime.NumGoroutine counts the whole process.
func bubbleGoroutines(t *testing.T) int {
	t.Helper()
	dump := allStacks()
	first, _, _ := bytes.Cut(dump, []byte("\n")) // runtime.Stack writes the caller's header first
	own := bubbleHeader.FindSubmatch(first)
	if own == nil {
		t.Fatal("no synctest bubble id in the caller's goroutine header: called outside a bubble, or the runtime changed the header format")
	}
	n := 0
	for _, m := range bubbleHeader.FindAllSubmatch(dump, -1) {
		if bytes.Equal(m[1], own[1]) {
			n++
		}
	}
	return n
}

func allStacks() []byte {
	for buf := make([]byte, 64<<10); ; buf = make([]byte, 2*len(buf)) {
		if n := runtime.Stack(buf, true); n < len(buf) {
			return buf[:n]
		}
	}
}

func TestBubbleGoroutinesIgnoresGoroutinesOutsideTheBubble(t *testing.T) {
	spawn, spawned, stop := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-spawn:
		case <-stop: // the bubble failed before close(spawn)
			return
		}
		for range 3 {
			go func() { <-stop }()
		}
		close(spawned)
	}()
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		baseline := bubbleGoroutines(t)

		go func() { <-release }()
		close(spawn)
		<-spawned
		synctest.Wait()

		assert.Equal(t, 1, bubbleGoroutines(t)-baseline)
	})
}
