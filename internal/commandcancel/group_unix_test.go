//go:build !windows

package commandcancel

import (
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminationReportsSurvivorsAfterEscalation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var signals []syscall.Signal
		start := time.Now()
		survivors, err := terminate(func(signal syscall.Signal) error { signals = append(signals, signal); return nil }, func() ([]int, error) { return []int{42, 43}, nil }, GracePeriod)
		require.NoError(t, err)
		assert.Equal(t, []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}, signals)
		assert.Equal(t, []int{42, 43}, survivors)
		assert.Equal(t, GracePeriod+100*time.Millisecond, time.Since(start))
	})
}
