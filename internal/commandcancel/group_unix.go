//go:build !windows

package commandcancel

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"
)

// TerminateGroup requires an owned, unreaped group leader. The caller must not
// Wait until this returns: the zombie leader pins the PGID throughout the grace period.
func TerminateGroup(pgid int, grace time.Duration) ([]int, error) {
	if pgid <= 0 {
		return nil, fmt.Errorf("invalid owned process group %d", pgid)
	}
	signal := func(sig syscall.Signal) error {
		err := syscall.Kill(-pgid, sig)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	return terminate(signal, func() ([]int, error) { return GroupMembers(pgid) }, grace)
}

func terminate(signal func(syscall.Signal) error, members func() ([]int, error), grace time.Duration) ([]int, error) {
	termErr := signal(syscall.SIGTERM)
	deadline := time.Now().Add(grace)
	for {
		alive, err := members()
		if err == nil && len(alive) == 0 {
			return nil, nil
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(min(10*time.Millisecond, time.Until(deadline)))
	}
	killErr := signal(syscall.SIGKILL)
	// A successful kill is asynchronous. Allow the kernel to finish scheduling it.
	deadline = time.Now().Add(100 * time.Millisecond)
	for {
		alive, err := members()
		if len(alive) == 0 || !time.Now().Before(deadline) || err != nil {
			return alive, errors.Join(termErr, killErr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func GroupMembers(pgid int) ([]int, error) {
	return matchingProcesses(func(pid int) bool { group, err := syscall.Getpgid(pid); return err == nil && group == pgid })
}

func matchingProcesses(matches func(int) bool) ([]int, error) {
	pids, err := process.Pids()
	if err != nil {
		return nil, err
	}
	var alive []int
	for _, pid := range pids {
		if !matches(int(pid)) {
			continue
		}
		if runtime.GOOS == "darwin" {
			alive = append(alive, int(pid))
			continue
		}
		p, err := process.NewProcess(pid)
		if err != nil {
			alive = append(alive, int(pid))
			continue
		}
		statuses, err := p.Status()
		if err == nil && slices.Contains(statuses, process.Zombie) {
			continue
		}
		alive = append(alive, int(pid))
	}
	slices.Sort(alive)
	return alive, nil
}

// TerminateSession includes job-control groups created by an interactive shell.
// The caller retains the unreaped session leader, pinning its SID. Each signal
// takes a fresh membership snapshot; PGIDs are never retained across the grace period.
// Unix has no atomic session signal: a job can exit between revalidation and
// kill, leaving a narrow PGID-reuse window, as in normal command exit cleanup.
func TerminateSession(sid int, grace time.Duration) ([]int, error) {
	if sid <= 0 {
		return nil, fmt.Errorf("invalid owned session %d", sid)
	}
	members := func() ([]int, error) {
		return matchingProcesses(func(pid int) bool { session, err := unix.Getsid(pid); return err == nil && session == sid })
	}
	signal := func(sig syscall.Signal) error {
		pids, err := members()
		if err != nil {
			return err
		}
		groups := make(map[int]bool)
		var errs []error
		for _, pid := range pids {
			pgid, err := syscall.Getpgid(pid)
			if err != nil || pgid <= 0 || groups[pgid] {
				continue
			}
			session, err := unix.Getsid(pid)
			if err != nil || session != sid {
				continue
			}
			currentGroup, err := syscall.Getpgid(pid)
			if err != nil || currentGroup != pgid {
				continue
			}
			groups[pgid] = true
			if err := syscall.Kill(-pgid, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	return terminate(signal, members, grace)
}
