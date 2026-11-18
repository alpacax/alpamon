//go:build !windows

package runner

import (
	"errors"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/v2/internal/commandcancel"
	"github.com/shirou/gopsutil/v4/process"
)

// stopSettle bounds how long Stop waits to observe every owned process
// stopped.
const stopSettle = time.Second

// groupProcessControl stops, continues and ends the process groups inside
// the process sessions a Work Session owns. Commands and terminals lead
// their own session, so a session holds a command's group, the children a
// finished command left in it and every job-control group of a terminal.
type groupProcessControl struct {
	mu sync.Mutex
	// stopped holds the groups a Stop suspended, per Work Session.
	stopped map[string]map[int]struct{}
	// cancel is the existing command cancel, applied by End to every owned
	// command and terminal.
	cancel func(commandID string)
	grace  time.Duration
}

func newProcessControl(cancel func(commandID string)) WorkSessionProcessController {
	return &groupProcessControl{stopped: map[string]map[int]struct{}{}, cancel: cancel, grace: commandcancel.GracePeriod}
}

// ownedMember is one live process of an owned session.
type ownedMember struct {
	session OwnedSession
	pid     int
	pgid    int
}

// ownedMembers lists the live processes of the owned sessions. A session
// whose leader PID now belongs to a process started later is not ours.
func ownedMembers(sessions []OwnedSession) []ownedMember {
	self := syscall.Getpgrp()
	var members []ownedMember
	for _, session := range sessions {
		if session.SID <= 1 || !sessionIdentity(session) {
			continue
		}
		pids, err := commandcancel.SessionMembers(session.SID)
		if err != nil {
			continue
		}
		for _, pid := range pids {
			pgid, err := syscall.Getpgid(pid)
			if err != nil || pgid <= 1 || pgid == self {
				continue
			}
			if state, err := processState(pid); err != nil || state == procZombie {
				continue
			}
			members = append(members, ownedMember{session: session, pid: pid, pgid: pgid})
		}
	}
	return members
}

// sessionIdentity reports whether the PID of the session's leader still
// names the leader the session was recorded with.
func sessionIdentity(session OwnedSession) bool {
	if session.StartedAt == 0 {
		return true
	}
	started := processStartedAt(session.SID)
	return started == 0 || started == session.StartedAt
}

func ownedSessionAlive(session OwnedSession) bool {
	return len(ownedMembers([]OwnedSession{session})) > 0
}

// processStartedAt returns the start time of pid in Unix milliseconds, or 0.
func processStartedAt(pid int) int64 {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return 0
	}
	started, err := p.CreateTime()
	if err != nil {
		return 0
	}
	return started
}

func groupsOf(members []ownedMember) []int {
	var groups []int
	for _, member := range members {
		groups = append(groups, member.pgid)
	}
	slices.Sort(groups)
	return slices.Compact(groups)
}

func treesOf(members []ownedMember) uint32 {
	var sids []int
	for _, member := range members {
		sids = append(sids, member.session.SID)
	}
	slices.Sort(sids)
	return uint32(len(slices.Compact(sids)))
}

func signalGroup(pgid int, sig syscall.Signal) error {
	if err := syscall.Kill(-pgid, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

func survivorOf(member ownedMember) WorkSessionSurvivor {
	return WorkSessionSurvivor{CommandID: member.session.CommandID, PID: member.pid, PGID: member.pgid}
}

// Stop sends SIGSTOP to every owned process group, again to any group that
// appears meanwhile, until every owned process is observed stopped.
func (c *groupProcessControl) Stop(id string, owned OwnedWork) (ProcessEffect, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	stopped := c.stopped[id]
	if stopped == nil {
		stopped = map[int]struct{}{}
		c.stopped[id] = stopped
	}

	var effect ProcessEffect
	var errs []error
	deadline := time.Now().Add(stopSettle)
	for {
		members := ownedMembers(owned.Sessions)
		if effect.AffectedTrees == 0 {
			effect.AffectedTrees = treesOf(members)
		}
		var running []ownedMember
		for _, member := range members {
			if state, err := processState(member.pid); err == nil && state != procStopped {
				running = append(running, member)
			}
		}
		if len(running) == 0 {
			return effect, errors.Join(errs...)
		}
		if !time.Now().Before(deadline) {
			effect.Survivors = []WorkSessionSurvivor{}
			for _, member := range running {
				effect.Survivors = append(effect.Survivors, survivorOf(member))
			}
			return effect, errors.Join(append(errs, errProcessSurvivors)...)
		}
		for _, pgid := range groupsOf(running) {
			if err := signalGroup(pgid, syscall.SIGSTOP); err != nil {
				errs = append(errs, err)
				continue
			}
			stopped[pgid] = struct{}{}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Continue sends SIGCONT to the groups a Stop suspended that are still
// owned, and to no other group.
func (c *groupProcessControl) Continue(id string, owned OwnedWork) (ProcessEffect, error) {
	c.mu.Lock()
	stopped := c.stopped[id]
	delete(c.stopped, id)
	c.mu.Unlock()
	if len(stopped) == 0 {
		return ProcessEffect{}, nil
	}

	var continued []ownedMember
	var errs []error
	members := ownedMembers(owned.Sessions)
	for _, pgid := range groupsOf(members) {
		if _, ok := stopped[pgid]; !ok {
			continue
		}
		if err := signalGroup(pgid, syscall.SIGCONT); err != nil {
			errs = append(errs, err)
			continue
		}
		for _, member := range members {
			if member.pgid == pgid {
				continued = append(continued, member)
			}
		}
	}
	return ProcessEffect{AffectedTrees: treesOf(continued)}, errors.Join(errs...)
}

// End cancels every owned command and terminal, then continues every owned
// group so a stopped process can act on TERM, and terminates each owned
// session with TERM and, after the grace period, KILL.
func (c *groupProcessControl) End(id string, owned OwnedWork) (ProcessEffect, error) {
	c.mu.Lock()
	delete(c.stopped, id)
	c.mu.Unlock()

	members := ownedMembers(owned.Sessions)
	var errs []error
	for _, pgid := range groupsOf(members) {
		if err := signalGroup(pgid, syscall.SIGCONT); err != nil {
			errs = append(errs, err)
		}
	}
	if c.cancel != nil {
		for _, commandID := range slices.Concat(owned.Commands, owned.Terminals) {
			c.cancel(commandID)
		}
	}

	effect := ProcessEffect{AffectedTrees: treesOf(members), Survivors: []WorkSessionSurvivor{}}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, session := range owned.Sessions {
		if !slices.ContainsFunc(members, func(m ownedMember) bool { return m.session.SID == session.SID }) {
			continue
		}
		wg.Go(func() {
			survivors, _, err := commandcancel.TerminateSession(session.SID, c.grace)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			}
			for _, pid := range survivors {
				pgid, _ := syscall.Getpgid(pid)
				effect.Survivors = append(effect.Survivors, WorkSessionSurvivor{CommandID: session.CommandID, PID: pid, PGID: pgid})
			}
		})
	}
	wg.Wait()
	if len(effect.Survivors) > 0 {
		errs = append(errs, errProcessSurvivors)
	}
	return effect, errors.Join(errs...)
}

// Inventory lists every live process of the owned sessions.
func (c *groupProcessControl) Inventory(owned OwnedWork) ([]WorkSessionProcess, error) {
	entries := []WorkSessionProcess{}
	for _, member := range ownedMembers(owned.Sessions) {
		state, err := processState(member.pid)
		if err != nil || state == procZombie {
			continue
		}
		entry := WorkSessionProcess{
			Kind:      member.session.Kind,
			CommandID: member.session.CommandID,
			PID:       member.pid,
			PGID:      member.pgid,
			State:     processRunning,
			Args:      []string{},
		}
		if state == procStopped {
			entry.State = processStopped
		}
		if started := processStartedAt(member.pid); started != 0 {
			entry.StartedAt = time.UnixMilli(started).UTC().Format(time.RFC3339Nano)
		}
		if p, err := process.NewProcess(int32(member.pid)); err == nil {
			if args, err := p.CmdlineSlice(); err == nil {
				entry.Args = cutArgs(args, workSessionArgsLimit)
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// procState is what processState observed of one process.
type procState int

const (
	procRunning procState = iota
	procStopped
	procZombie
)
