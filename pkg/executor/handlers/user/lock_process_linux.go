package user

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const processTerminationBound = 5 * time.Second

type accountProcess interface {
	pid() int
	stop() error
	stopped() (bool, error)
	kill() error
	alive() (bool, error)
	close()
}

type processScanner func(uint64, map[int]accountProcess) ([]accountProcess, error)

type pidfdProcess struct {
	id int
	fd int
}

func (p *pidfdProcess) pid() int    { return p.id }
func (p *pidfdProcess) close()      { _ = unix.Close(p.fd) }
func (p *pidfdProcess) stop() error { return p.signal(unix.SIGSTOP) }
func (p *pidfdProcess) kill() error { return p.signal(unix.SIGKILL) }

func (p *pidfdProcess) signal(signal unix.Signal) error {
	err := unix.PidfdSendSignal(p.fd, signal, nil, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func (p *pidfdProcess) alive() (bool, error) {
	fds := []unix.PollFd{{Fd: int32(p.fd), Events: unix.POLLIN}}
	for {
		_, err := unix.Poll(fds, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false, err
		}
		if fds[0].Revents&(unix.POLLNVAL|unix.POLLERR) != 0 {
			return false, fmt.Errorf("cannot poll process handle")
		}
		return fds[0].Revents == 0, nil
	}
}

func (p *pidfdProcess) stopped() (bool, error) {
	live, err := p.alive()
	if err != nil || !live {
		return true, err
	}
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", p.id))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	stopped := true
	for _, task := range tasks {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/status", p.id, task.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		state := statusField(string(data), "State:")
		if len(state) == 0 || !strings.ContainsAny(state[:1], "TtZX") {
			stopped = false
		}
	}
	// The handle must still name a live task after reading /proc by number.
	// If it exited during the read, no information from a reused PID is used.
	live, err = p.alive()
	return stopped || !live, err
}

func terminateAccountProcesses(ctx context.Context, uid uint64, terminateSessions func(context.Context) error) (int, error) {
	return endAccountProcesses(ctx, uid, terminateSessions, scanAccountProcesses)
}

func endAccountProcesses(ctx context.Context, uid uint64, terminateSessions func(context.Context) error, scan processScanner) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, processTerminationBound)
	defer cancel()
	tracked := make(map[int]accountProcess)
	defer func() {
		// Even a failed scan or cancellation must not leave a frozen tree.
		for _, p := range tracked {
			_ = p.kill()
			p.close()
		}
	}()
	count := 0
	first := true
	var sessionErr error
	for {
		if err := ctx.Err(); err != nil {
			return count, errors.Join(err, sessionErr)
		}
		processes, err := scan(uid, tracked)
		if err != nil {
			return count, errors.Join(err, sessionErr)
		}
		if first {
			count = len(processes)
			first = false
		}
		for _, p := range processes {
			tracked[p.pid()] = p
		}
		for _, p := range processes {
			if err := p.stop(); err != nil {
				return count, err
			}
		}
		allStopped := true
		for _, p := range tracked {
			stopped, err := p.stopped()
			if err != nil {
				return count, err
			}
			allStopped = allStopped && stopped
		}
		// A fresh scan after all threads stop captures children forked while
		// SIGSTOP was pending, including descendants with a different UID.
		if len(processes) > 0 || !allStopped {
			if err := waitProcessScan(ctx); err != nil {
				return count, err
			}
			continue
		}
		if terminateSessions != nil {
			// Leave time for pidfd cleanup when logind fails or stalls. A user
			// without a logind record can still have processes to terminate.
			sessionCtx, sessionCancel := context.WithTimeout(ctx, time.Second)
			sessionErr = terminateSessions(sessionCtx)
			sessionCancel()
			terminateSessions = nil
		}
		for _, p := range tracked {
			if err := p.kill(); err != nil {
				return count, err
			}
		}
		for id, p := range tracked {
			live, err := p.alive()
			if err != nil {
				return count, err
			}
			if !live {
				p.close()
				delete(tracked, id)
			}
		}
		// Rescan after killing: services outside logind can restart under
		// this UID. They must disappear within the same bounded operation.
		if len(tracked) == 0 {
			remaining, err := scan(uid, tracked)
			if err != nil {
				return count, err
			}
			for _, p := range remaining {
				tracked[p.pid()] = p
			}
			for _, p := range remaining {
				if err := p.stop(); err != nil {
					return count, err
				}
			}
			if len(remaining) == 0 {
				return count, sessionErr
			}
		}
		if err := waitProcessScan(ctx); err != nil {
			return count, errors.Join(err, sessionErr)
		}
	}
}

func waitProcessScan(ctx context.Context) error {
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func scanAccountProcesses(uid uint64, tracked map[int]accountProcess) (result []accountProcess, err error) {
	defer func() {
		if err != nil {
			for _, p := range result {
				p.close()
			}
		}
	}()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		id, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || id <= 0 {
			continue
		}
		if _, ok := tracked[id]; ok {
			continue
		}
		path := filepath.Join("/proc", entry.Name(), "status")
		data, readErr := os.ReadFile(path)
		if errors.Is(readErr, os.ErrNotExist) || errors.Is(readErr, unix.ESRCH) {
			continue
		}
		if readErr != nil {
			return result, readErr
		}
		if !matchesAccountProcess(string(data), uid, tracked) {
			continue
		}
		fd, openErr := unix.PidfdOpen(id, 0)
		if errors.Is(openErr, unix.ESRCH) {
			continue
		}
		if openErr != nil {
			return result, fmt.Errorf("cannot open process handle: %w", openErr)
		}
		p := &pidfdProcess{id: id, fd: fd}
		// Re-read identity after acquiring the handle, then prove it remained
		// live through the read. Signals only ever use this pidfd.
		data, readErr = os.ReadFile(path)
		live, liveErr := p.alive()
		if readErr != nil || liveErr != nil || !live || !matchesAccountProcess(string(data), uid, tracked) {
			p.close()
			if liveErr != nil {
				return result, liveErr
			}
			if readErr != nil && !errors.Is(readErr, os.ErrNotExist) && !errors.Is(readErr, unix.ESRCH) {
				return result, readErr
			}
			continue
		}
		result = append(result, p)
	}
	return result, nil
}

func matchesAccountProcess(status string, uid uint64, tracked map[int]accountProcess) bool {
	// Real and saved UIDs identify the account; effective and filesystem UIDs
	// can belong to root daemon workers temporarily impersonating the user.
	for index, field := range strings.Fields(statusField(status, "Uid:")) {
		if index != 0 && index != 2 {
			continue
		}
		value, err := strconv.ParseUint(field, 10, 32)
		if err == nil && value == uid {
			return true
		}
	}
	parent, err := strconv.Atoi(statusField(status, "PPid:"))
	if err != nil {
		return false
	}
	if p, ok := tracked[parent]; ok {
		live, err := p.alive()
		return err == nil && live
	}
	return false
}

func statusField(status, key string) string {
	for line := range strings.SplitSeq(status, "\n") {
		if strings.HasPrefix(line, key) {
			return strings.TrimSpace(strings.TrimPrefix(line, key))
		}
	}
	return ""
}

func probeProcessHandles(open func(int, int) (int, error)) error {
	fd, err := open(os.Getpid(), 0)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOSYS):
			return fmt.Errorf("unsupported_kernel: process handles require Linux 5.3 or later")
		case errors.Is(err, unix.EPERM):
			return fmt.Errorf("unsupported_kernel: process handles are blocked (%v)", err)
		default:
			return fmt.Errorf("process_probe_failed: %w", err)
		}
	}
	return unix.Close(fd)
}
