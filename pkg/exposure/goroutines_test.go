package exposure

import (
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
	own := bubbleHeader.FindSubmatch(stack(false))
	if own == nil {
		t.Fatal("bubbleGoroutines called outside a synctest bubble")
	}
	n := 0
	for _, m := range bubbleHeader.FindAllSubmatch(stack(true), -1) {
		if string(m[1]) == string(own[1]) {
			n++
		}
	}
	return n
}

func stack(all bool) []byte {
	for buf := make([]byte, 64<<10); ; buf = make([]byte, 2*len(buf)) {
		if n := runtime.Stack(buf, all); n < len(buf) {
			return buf[:n]
		}
	}
}

func TestBubbleGoroutinesIgnoresGoroutinesOutsideTheBubble(t *testing.T) {
	spawn, spawned, stop := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(stop)
	go func() {
		<-spawn
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
