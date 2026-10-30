package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"time"

	"github.com/alpacax/alpamon/v2/internal/commandcancel"
)

// Own the pipe drain so the leader stays unreaped until cancellation can no
// longer arrive. exec.Cmd.Wait otherwise reaps before waiting on inherited pipes.
func runTrackedCommand(ctx context.Context, cmd *exec.Cmd, cleanup *commandCleanup, cw *chunkWriter, pidHook func(int), commandID string) ([]byte, error) {
	state := commandcancel.FromContext(ctx)
	return runTrackedProcessCommand(ctx, cmd, cleanup, cw, pidHook, commandID, state, commandcancel.GracePeriod)
}

func runTrackedProcessCommand(ctx context.Context, cmd *exec.Cmd, cleanup *commandCleanup, cw *chunkWriter, pidHook func(int), commandID string, state *commandcancel.State, grace time.Duration) ([]byte, error) {
	defer func() { _ = cleanup.close() }()
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()
	cmd.Stdout, cmd.Stderr = writer, writer
	cmd.Cancel = nil
	cmd.WaitDelay = 0
	var buf bytes.Buffer
	var sink io.Writer = &buf
	if cw != nil {
		sink = cw
	}
	finish := func(err error) ([]byte, error) {
		if cw != nil {
			cw.close()
			return cw.captured(), err
		}
		return buf.Bytes(), err
	}
	if err := cmd.Start(); err != nil {
		if errors.Is(err, context.Canceled) {
			state.Observe()
		}
		return finish(err)
	}
	cmd.WaitDelay = commandWaitDelay
	_ = writer.Close()
	if err := cleanup.afterStart(cmd); err != nil {
		_, _ = cleanup.cancel(cmd)
		_ = cmd.Wait()
		return finish(err)
	}
	if cw != nil {
		cw.start(chunkFlushInterval)
	}
	invokePIDHook(pidHook, cmd.Process.Pid)
	copied := make(chan error, 1)
	go func() { _, err := io.Copy(sink, reader); copied <- err }()
	exited, watchErr := watchCommandExit(cmd, cleanup)
	if watchErr != nil {
		_, _ = cleanup.cancel(cmd)
		_ = reader.Close()
		<-copied
		_ = cmd.Wait()
		return finish(watchErr)
	}

	var exitObserved, outputDone, cancelled, pipeExpired, reapLater, remoteEffective bool
	var copyErr, observeErr, cancelErr error
	var timer *time.Timer
	var deadline <-chan time.Time
	var waitDeadline time.Time
	done := ctx.Done()
	startTimer := func() {
		if timer == nil {
			waitDeadline = time.Now().Add(commandWaitDelay)
			timer = time.NewTimer(commandWaitDelay)
			deadline = timer.C
		}
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for !exitObserved || !outputDone {
		select {
		case <-done:
			done = nil
			cancelled = true
			if errors.Is(context.Cause(ctx), commandcancel.ErrCancelled) {
				outcome, err := cleanup.cancelRemote(cmd, grace)
				remoteEffective = outcome.killedAny()
				survivors := outcome.survivors
				if state != nil {
					state.AddSurvivors(survivors)
					if outcome.killedAny() {
						state.Observe()
					}
				}
				cancelErr = err
				if slices.Contains(survivors, cmd.Process.Pid) || err != nil {
					reapLater = true
					exitObserved = true
					_ = reader.Close()
				}
				logProcessTreeCleanup(commandID, cmd, "cancel", outcome, err)
			} else {
				outcome, err := cleanup.cancel(cmd)
				cancelErr = err
				reason := cleanupReasonShutdown
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					reason = cleanupReasonTimeout
				}
				logProcessTreeCleanup(commandID, cmd, reason, outcome, err)
			}
			startTimer()
		case observeErr = <-exited:
			exited = nil
			exitObserved = true
			if observeErr != nil {
				_, _ = cleanup.cancel(cmd)
			}
			startTimer()
		case copyErr = <-copied:
			copied = nil
			outputDone = true
		case <-deadline:
			deadline = nil
			if !outputDone {
				pipeExpired = true
				_ = reader.Close()
			}
		}
	}
	cmd.WaitDelay = max(time.Nanosecond, time.Until(waitDeadline))
	if reapLater {
		// No more signals: the outstanding observer and waiter only reap the owned
		// child if the kernel eventually lets an uninterruptible survivor exit.
		go func() {
			if exited != nil {
				<-exited
			}
			_ = cmd.Wait()
		}()
		if cancelErr != nil {
			return finish(cancelErr)
		}
		return finish(ctx.Err())
	}
	// Explicit cancellation has completed while the leader was pinned. The
	// normal path retains the existing post-Wait cleanup order.
	waitErr := cmd.Wait()
	if !cancelled {
		outcome, cleanupErr := cleanup.cancel(cmd)
		reason := cleanupReasonExit
		if pipeExpired || errors.Is(waitErr, exec.ErrWaitDelay) {
			reason = cleanupReasonWaitDelay
		}
		logProcessTreeCleanup(commandID, cmd, reason, outcome, cleanupErr)
	}
	if waitErr == nil {
		switch {
		case observeErr != nil:
			waitErr = observeErr
		case cancelled && cancelErr != nil && !errors.Is(cancelErr, os.ErrProcessDone):
			waitErr = cancelErr
		case cancelled && (!errors.Is(context.Cause(ctx), commandcancel.ErrCancelled) || remoteEffective):
			waitErr = ctx.Err()
		case pipeExpired:
			waitErr = exec.ErrWaitDelay
		case copyErr != nil:
			waitErr = copyErr
		}
	}
	return finish(waitErr)
}
