package base

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckBuffer_PublishSuccessReturnsNilOnceQueued(t *testing.T) {
	buffer := NewCheckBuffer(1)

	err := buffer.PublishSuccess(context.Background(), MetricData{Type: CPU})

	require.NoError(t, err)
	assert.Len(t, buffer.SuccessQueue, 1)
}

func TestCheckBuffer_PublishSuccessReturnsCtxErrWhenQueueFullAndCtxCancelled(t *testing.T) {
	buffer := NewCheckBuffer(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := buffer.PublishSuccess(ctx, MetricData{Type: CPU})

	assert.ErrorIs(t, err, context.Canceled)
}

func TestCheckBuffer_PublishFailureReturnsNilOnceQueued(t *testing.T) {
	buffer := NewCheckBuffer(1)

	err := buffer.PublishFailure(context.Background(), MetricData{Type: Mem})

	require.NoError(t, err)
	assert.Len(t, buffer.FailureQueue, 1)
}

func TestCheckBuffer_PublishFailureReturnsCtxErrWhenQueueFullAndCtxCancelled(t *testing.T) {
	buffer := NewCheckBuffer(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := buffer.PublishFailure(ctx, MetricData{Type: Mem})

	assert.ErrorIs(t, err, context.Canceled)
}

func TestCheckBuffer_PublishSuccessBlocksUntilCtxCancelledWhenQueueFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buffer := NewCheckBuffer(0)
		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan error, 1)
		go func() {
			done <- buffer.PublishSuccess(ctx, MetricData{Type: CPU})
		}()

		time.Sleep(50 * time.Millisecond)
		synctest.Wait()

		select {
		case <-done:
			t.Fatal("PublishSuccess returned before ctx was cancelled and nothing drained the queue")
		default:
		}

		cancel()

		select {
		case err := <-done:
			assert.ErrorIs(t, err, context.Canceled)
		case <-time.After(time.Second):
			t.Fatal("PublishSuccess did not return after ctx was cancelled")
		}
	})
}
