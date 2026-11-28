//go:build !windows

package executor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutor_ProcessStartGuardRefusesActualStart(t *testing.T) {
	refused := errors.New("session paused before process start")
	ctx := common.WithProcessStartGuard(context.Background(), func() (func(), error) {
		return nil, refused
	})
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "printf started")
	_, err := NewExecutor().runCommand(ctx, cmd, "", nil, nil)
	assert.ErrorIs(t, err, refused)
	assert.Nil(t, cmd.Process, "a command admitted before Pause must still be fenced at Start")
}

func TestExecutor_ProcessStartGuardSpansObservationWithoutHoldingWait(t *testing.T) {
	for _, observerPanics := range []bool{false, true} {
		t.Run(map[bool]string{false: "observer returns", true: "observer panics"}[observerPanics], func(t *testing.T) {
			reader, writer, err := os.Pipe()
			require.NoError(t, err)
			t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
			var held, observed bool
			var releases int
			var inputErr error
			ctx := common.WithProcessStartGuard(context.Background(), func() (func(), error) {
				held = true
				return func() {
					held = false
					releases++
					_, inputErr = writer.Write([]byte("ready\n"))
				}, nil
			})
			ctx = common.WithProcessObserver(ctx, func(_ string, _ int) {
				assert.True(t, held, "Stop must wait until the started process is registered")
				observed = true
				if observerPanics {
					panic("observer failed")
				}
			})
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "read value; printf completed")
			cmd.Stdin = reader
			output, err := NewExecutor().runCommand(ctx, cmd, "", nil, nil)
			require.NoError(t, err)
			require.NoError(t, inputErr)
			assert.Equal(t, "completed", string(output))
			assert.True(t, observed)
			assert.False(t, held)
			assert.Equal(t, 1, releases)
		})
	}
}

func TestExecutor_ProcessStartGuardReleasesWhenStartFails(t *testing.T) {
	var releases int
	ctx := common.WithProcessStartGuard(context.Background(), func() (func(), error) {
		return func() { releases++ }, nil
	})
	cmd := exec.CommandContext(ctx, "/no/such/executable/start-guard-regression")
	_, err := NewExecutor().runCommand(ctx, cmd, "", nil, nil)
	require.Error(t, err)
	assert.Equal(t, 1, releases, "a failed Start must not retain the action lock")
}
