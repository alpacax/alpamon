//go:build darwin || windows

package runner

import "testing"

func stubCollectCommand(t *testing.T, err error) {
	t.Helper()
	previous := runCollectCommand
	t.Cleanup(func() { runCollectCommand = previous })
	runCollectCommand = func(string, ...string) ([]byte, error) { return nil, err }
}
