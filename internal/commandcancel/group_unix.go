//go:build !windows

package commandcancel

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"runtime"
	"slices"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"
)

// TerminateGroup requires an owned, unreaped group leader. The caller must not
// Wait until this returns: the zombie leader pins the PGID throughout the grace period.
func TerminateGroup(pgid int, grace time.Duration) ([]int, bool, error) {
	if pgid <= 1 {
		return nil, false, fmt.Errorf("invalid owned process group %d", pgid)
	}
	signalled := false
	signal := func(sig syscall.Signal) error {
		alive, err := GroupMembers(pgid)
		if err != nil || len(alive) == 0 {
			return err
		}
		err = syscall.Kill(-pgid, sig)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err == nil {
			signalled = true
		}
		return err
	}
	survivors, err := terminate(signal, func() ([]int, error) { return GroupMembers(pgid) }, grace)
	return survivors, signalled, err
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
		time.Sleep(min(50*time.Millisecond, time.Until(deadline)))
	}
	killErr := signal(syscall.SIGKILL)
	// A successful kill is asynchronous. Allow the kernel to finish scheduling it.
	deadline = time.Now().Add(100 * time.Millisecond)
	for {
		alive, err := members()
		if len(alive) == 0 || !time.Now().Before(deadline) || err != nil {
			return alive, errors.Join(termErr, killErr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func GroupMembers(pgid int) ([]int, error) {
	return matchingProcesses(func(pid int) (bool, error) { group, err := syscall.Getpgid(pid); return group == pgid, err })
}

func matchingProcesses(matches func(int) (bool, error)) ([]int, error) {
	pids, err := process.Pids()
	if err != nil {
		return nil, err
	}
	var alive []int
	var errs []error
	for _, pid := range pids {
		matched, err := matches(int(pid))
		if err != nil {
			if !processGone(err) {
				errs = append(errs, err)
			}
			continue
		}
		if !matched {
			continue
		}
		if runtime.GOOS == "darwin" {
			alive = append(alive, int(pid))
			continue
		}
		p, err := process.NewProcess(pid)
		if err != nil {
			if processGone(err) {
				continue
			}
			errs = append(errs, err)
			alive = append(alive, int(pid))
			continue
		}
		statuses, err := p.Status()
		if err != nil {
			if processGone(err) {
				continue
			}
			errs = append(errs, err)
		}
		if err == nil && slices.Contains(statuses, process.Zombie) {
			continue
		}
		alive = append(alive, int(pid))
	}
	slices.Sort(alive)
	return alive, errors.Join(errs...)
}

// TerminateSession includes job-control groups created by an interactive shell.
// The caller pins the SID: it retains the unreaped session leader, or it holds
// a live member it verified by start time, since a SID with a live member is
// never handed to a new session. Each signal takes a fresh membership snapshot;
// PGIDs are never retained across the grace period.
// Each signal goes through SignalSessionGroups, so a job group is reached
// only through its members' pidfds, or not at all where the host has none:
// its members are then reported as survivors.
func TerminateSession(sid int, grace time.Duration) ([]int, bool, error) {
	if sid <= 1 {
		return nil, false, fmt.Errorf("invalid owned session %d", sid)
	}
	signalled := false
	survivors, err := terminate(func(sig syscall.Signal) error {
		sent, err := signalSession(sid, sig)
		signalled = signalled || sent
		return err
	}, func() ([]int, error) { return SessionMembers(sid) }, grace)
	return survivors, signalled, err
}

// ErrSessionUnverified reports members left in a session whose identity
// could no longer be proven, so they were not signalled.
var ErrSessionUnverified = errors.New("session identity no longer verified")

// TerminateVerifiedSession is TerminateSession for a caller that pins sid by
// a live member rather than by the unreaped leader, which TERM can end.
// verified lists the members that still prove the session's identity, and
// false once none does; every signal and every poll checks it first. Once it
// fails no signal is sent, and the members still in the session are reported
// as survivors with ErrSessionUnverified.
func TerminateVerifiedSession(sid int, grace time.Duration, verified func() ([]int, bool)) ([]int, bool, error) {
	if sid <= 1 {
		return nil, false, fmt.Errorf("invalid owned session %d", sid)
	}
	signalled, lost := false, false
	members := func() ([]int, error) {
		if !lost {
			alive, ok := verified()
			if ok {
				return alive, nil
			}
			lost = true
		}
		return SessionMembers(sid)
	}
	survivors, err := terminate(func(sig syscall.Signal) error {
		if lost {
			return nil
		}
		if _, ok := verified(); !ok {
			lost = true
			return nil
		}
		sent, err := signalSession(sid, sig)
		signalled = signalled || sent
		return err
	}, members, grace)
	if lost && len(survivors) > 0 {
		err = errors.Join(err, ErrSessionUnverified)
	}
	return survivors, signalled, err
}

// HangupSession sends only SIGHUP. Jobs that ignore it may outlive the terminal.
// The caller retains the unreaped session leader until this returns.
func HangupSession(sid int) error {
	if sid <= 1 {
		return fmt.Errorf("invalid owned session %d", sid)
	}
	_, err := signalSession(sid, syscall.SIGHUP)
	return err
}

func SessionMembers(sid int) ([]int, error) {
	return matchingProcesses(func(pid int) (bool, error) { session, err := unix.Getsid(pid); return session == sid, err })
}

func processGone(err error) bool {
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, os.ErrNotExist) || errors.Is(err, process.ErrorProcessNotRunning)
}

// SessionMember records a process identity and its observed process group.
type SessionMember struct {
	StartedAt int64
	PGID      int
}

type pinnedSignalOps struct {
	started func(int) (int64, error)
	sid     func(int) (int, error)
	pgid    func(int) (int, error)
	signal  func(int, syscall.Signal) error
	// pidfd is nil on a host that cannot hold a process through signal
	// delivery.
	pidfd *pidfdOps
	// leader runs a signal only while its pid is a child alpamon has not
	// reaped, and reports whether it ran.
	leader  func(int, func() error) (bool, error)
	members func(int) ([]int, error)
}

// pidfdOps opens a handle that keeps referring to one process after it
// exits, so a signal sent through it never reaches a process that reused
// its PID.
type pidfdOps struct {
	open  func(pid int) (int, error)
	send  func(fd int, sig syscall.Signal) error
	close func(fd int) error
}

// ErrSignalNotHeld reports a host that cannot keep a verified process's
// identity through signal delivery: a signal could reach a process that
// reused a verified PID or PGID.
var ErrSignalNotHeld = fmt.Errorf("process identity cannot be held through signal delivery: %w", errors.ErrUnsupported)

func systemPinnedSignalOps() pinnedSignalOps {
	return pinnedSignalOps{started: memberStartedAt, sid: unix.Getsid, pgid: syscall.Getpgid, signal: syscall.Kill, pidfd: systemPidfd(), leader: withHeldLeader, members: SessionMembers}
}

func memberStartedAt(pid int) (int64, error) {
	return ProcessStartTime(pid)
}

// PinnedSignalsHeld reports whether SignalPinnedSessionMembers can signal on
// this host.
func PinnedSignalsHeld() bool {
	return systemPidfd() != nil
}

// SignalPinnedSessionMembers signals each supplied member through a handle
// that holds the process, after checking the member through that handle, and
// returns the groups of the members it signalled. It never signals a PGID.
// It returns ErrSignalNotHeld, and signals nothing, on a host that cannot
// hold a process.
func SignalPinnedSessionMembers(sid int, members map[int]SessionMember, sig syscall.Signal) ([]int, error) {
	return signalHeldSessionMembers(sid, members, sig, systemPinnedSignalOps())
}

func signalHeldSessionMembers(sid int, members map[int]SessionMember, sig syscall.Signal, ops pinnedSignalOps) ([]int, error) {
	if ops.pidfd == nil {
		return nil, ErrSignalNotHeld
	}
	return signalPinnedSessionGroups(sid, members, sig, ops)
}

// SignalPinnedSessionGroups is SignalPinnedSessionMembers where the host can
// hold a process. Elsewhere it signals by PGID only the group of the session
// leader, and only while alpamon holds that leader unreaped (HoldLeader), so
// the PGID cannot be reused before delivery. It signals no other group: their
// members are left for the caller to report.
func SignalPinnedSessionGroups(sid int, members map[int]SessionMember, sig syscall.Signal) ([]int, error) {
	return signalPinnedSessionGroups(sid, members, sig, systemPinnedSignalOps())
}

func signalPinnedSessionGroups(sid int, members map[int]SessionMember, sig syscall.Signal, ops pinnedSignalOps) ([]int, error) {
	if sid <= 1 {
		return nil, fmt.Errorf("invalid owned session %d", sid)
	}
	var groups []int
	var errs []error
	for _, pid := range slices.Sorted(maps.Keys(members)) {
		member := members[pid]
		if ops.pidfd == nil && slices.Contains(groups, member.PGID) {
			continue
		}
		if pid <= 1 || member.StartedAt == 0 || member.PGID <= 1 {
			errs = append(errs, ErrSessionUnverified)
			continue
		}
		var err error
		if ops.pidfd != nil {
			err = signalHeldMember(sid, pid, member, sig, ops)
		} else {
			err = signalMemberGroup(sid, pid, member, sig, ops)
		}
		if err != nil {
			if !processGone(err) && !errors.Is(err, errLeaderNotHeld) {
				errs = append(errs, err)
			}
			if errors.Is(err, ErrSignalNotHeld) {
				break
			}
			continue
		}
		if !slices.Contains(groups, member.PGID) {
			groups = append(groups, member.PGID)
		}
	}
	return groups, errors.Join(errs...)
}

// signalHeldMember checks the member once more after its pidfd is open: a
// PID reused before the open fails that check, and one reused after the
// check is not the process the pidfd holds.
func signalHeldMember(sid, pid int, member SessionMember, sig syscall.Signal, ops pinnedSignalOps) error {
	if err := checkPinnedMember(sid, pid, member, ops); err != nil {
		return err
	}
	fd, err := ops.pidfd.open(pid)
	if errors.Is(err, syscall.ENOSYS) {
		return ErrSignalNotHeld
	}
	if err != nil {
		return err
	}
	defer func() { _ = ops.pidfd.close(fd) }()
	if err := checkPinnedMember(sid, pid, member, ops); err != nil {
		return err
	}
	return ops.pidfd.send(fd, sig)
}

// errLeaderNotHeld marks a member whose group no unreaped leader pins; it is
// not signalled and not an error.
var errLeaderNotHeld = errors.New("process group leader is not held")

func signalMemberGroup(sid, pid int, member SessionMember, sig syscall.Signal, ops pinnedSignalOps) error {
	for range 2 {
		if err := checkPinnedMember(sid, pid, member, ops); err != nil {
			return err
		}
	}
	if member.PGID != sid || ops.leader == nil {
		return errLeaderNotHeld
	}
	held, err := ops.leader(sid, func() error { return ops.signal(-sid, sig) })
	if !held {
		return errLeaderNotHeld
	}
	return err
}

func checkPinnedMember(sid, pid int, member SessionMember, ops pinnedSignalOps) error {
	started, err := ops.started(pid)
	if err != nil {
		return err
	}
	if started != member.StartedAt {
		return ErrSessionUnverified
	}
	current, err := ops.sid(pid)
	if err != nil {
		return err
	}
	if current != sid {
		return ErrSessionUnverified
	}
	current, err = ops.pgid(pid)
	if err != nil {
		return err
	}
	if current != member.PGID {
		return ErrSessionUnverified
	}
	return nil
}

// TerminatePinnedSession refreshes identities before each termination signal.
func TerminatePinnedSession(sid int, grace time.Duration, verified func() (map[int]SessionMember, error)) ([]int, bool, error) {
	return terminatePinnedSession(sid, grace, verified, SignalPinnedSessionGroups, SessionMembers)
}

func terminatePinnedSession(sid int, grace time.Duration, verified func() (map[int]SessionMember, error), signal func(int, map[int]SessionMember, syscall.Signal) ([]int, error), list func(int) ([]int, error)) ([]int, bool, error) {
	if sid <= 1 {
		return nil, false, fmt.Errorf("invalid owned session %d", sid)
	}
	sent, lost := false, false
	var errs []error
	lookup := func() (map[int]SessionMember, error) {
		members, err := verified()
		if err == nil && members == nil {
			err = ErrSessionUnverified
		}
		if err != nil {
			lost = true
			errs = append(errs, err)
		}
		return members, err
	}
	survivors, err := terminate(func(sig syscall.Signal) error {
		if lost {
			return nil
		}
		members, err := lookup()
		if err != nil {
			return err
		}
		groups, err := signal(sid, members, sig)
		sent = sent || len(groups) > 0
		if err != nil {
			errs = append(errs, err)
			lost = true
		}
		return err
	}, func() ([]int, error) {
		if !lost {
			members, err := lookup()
			if err == nil {
				return slices.Sorted(maps.Keys(members)), nil
			}
		}
		members, err := list(sid)
		return members, errors.Join(append(errs, err)...)
	}, grace)
	return survivors, sent, errors.Join(append(errs, err)...)
}

func signalSession(sid int, sig syscall.Signal) (bool, error) {
	groups, err := SignalSessionGroups(sid, sig, nil)
	return len(groups) > 0, err
}

// SignalSessionGroups sends sig to each process group of session sid that
// include admits, or to every group when include is nil, and returns the
// groups it reached. The caller pins sid as TerminateSession requires. Each
// member is taken from a fresh membership snapshot and its SID and PGID are
// read again right before the signal, so a process that left the session is
// never signalled. Where the host holds a process, each member is signalled
// through its pidfd and no PGID is signalled. Elsewhere only the session
// leader's group is signalled by PGID, and only while alpamon holds that
// leader unreaped (HoldLeader); the members of any other group are left for
// the caller to report.
func SignalSessionGroups(sid int, sig syscall.Signal, include func(pgid int) bool) ([]int, error) {
	return signalSessionGroups(sid, sig, include, systemPinnedSignalOps())
}

func signalSessionGroups(sid int, sig syscall.Signal, include func(pgid int) bool, ops pinnedSignalOps) ([]int, error) {
	if sid <= 1 {
		return nil, fmt.Errorf("invalid owned session %d", sid)
	}
	pids, err := ops.members(sid)
	if err != nil {
		return nil, err
	}
	var signalled []int
	tried := make(map[int]bool)
	var errs []error
	for _, pid := range pids {
		pgid, err := ops.pgid(pid)
		if err != nil || pgid <= 1 || tried[pgid] || include != nil && !include(pgid) {
			continue
		}
		var sent bool
		if ops.pidfd != nil {
			sent, err = signalSessionMember(sid, pid, pgid, sig, ops)
		} else {
			sent, err = signalLeaderGroup(sid, pid, pgid, sig, ops)
			tried[pgid] = tried[pgid] || sent || err != nil
		}
		if err != nil && !processGone(err) {
			errs = append(errs, err)
		}
		if sent && !slices.Contains(signalled, pgid) {
			signalled = append(signalled, pgid)
		}
	}
	return signalled, errors.Join(errs...)
}

// sessionMemberOf reports whether pid is still in session sid and group pgid.
func sessionMemberOf(sid, pid, pgid int, ops pinnedSignalOps) bool {
	session, err := ops.sid(pid)
	if err != nil || session != sid {
		return false
	}
	current, err := ops.pgid(pid)
	return err == nil && current == pgid
}

// signalSessionMember checks pid's session and group through its open pidfd:
// a PID reused before the open fails the check, and one reused after it is
// not the process the pidfd holds.
func signalSessionMember(sid, pid, pgid int, sig syscall.Signal, ops pinnedSignalOps) (bool, error) {
	fd, err := ops.pidfd.open(pid)
	if errors.Is(err, syscall.ENOSYS) {
		return false, ErrSignalNotHeld
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = ops.pidfd.close(fd) }()
	if !sessionMemberOf(sid, pid, pgid, ops) {
		return false, nil
	}
	if err := ops.pidfd.send(fd, sig); err != nil {
		return false, err
	}
	return true, nil
}

// signalLeaderGroup signals the session leader's group while alpamon holds
// the leader unreaped, and no other group.
func signalLeaderGroup(sid, pid, pgid int, sig syscall.Signal, ops pinnedSignalOps) (bool, error) {
	if pgid != sid || ops.leader == nil || !sessionMemberOf(sid, pid, pgid, ops) {
		return false, nil
	}
	held, err := ops.leader(sid, func() error { return ops.signal(-sid, sig) })
	return held && err == nil, err
}
