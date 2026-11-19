//go:build !windows

package runner

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/v2/internal/commandcancel"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/process"
)

// stopSettle bounds how long Stop waits to observe every owned process
// stopped.
const stopSettle = time.Second

// groupProcessControl stops, continues and ends the process groups inside
// the process sessions a Work Session owns. Commands and terminals lead
// their own session, so a session holds a command's group, the children a
// finished command left in it and every job-control group of a terminal.
// Every signal goes through commandcancel, which reads a member's SID and
// PGID again right before it signals the member's group.
type groupProcessControl struct {
	mu sync.Mutex
	// stopped holds the groups a Stop suspended, per Work Session, each with
	// the members that pin its identity until Resume.
	stopped map[string]map[groupKey]*stoppedGroup
	// cancel is the existing command cancel, applied by End to every owned
	// command and terminal.
	cancel    func(commandID string)
	grace     time.Duration
	readState func(int) (procState, error)
}

func newProcessControl(cancel func(commandID string)) WorkSessionProcessController {
	return &groupProcessControl{stopped: map[string]map[groupKey]*stoppedGroup{}, cancel: cancel, grace: commandcancel.GracePeriod, readState: processState}
}

// sessionKey names one owned process session: its SID and its leader's
// start time.
type sessionKey struct {
	sid       int
	startedAt int64
}

func keyOf(session OwnedSession) sessionKey {
	return sessionKey{sid: session.SID, startedAt: session.StartedAt}
}

// groupKey names one process group inside an owned process session.
type groupKey struct {
	session sessionKey
	pgid    int
}

// stoppedGroup is a group a Stop suspended. Resume continues it only while
// one of members, by PID and start time, is still in it: a live member keeps
// the PGID from being handed to another group.
type stoppedGroup struct {
	members map[int]int64
}

// sessionPin is what proves an owned process session is still the one
// recorded once its leader is gone: the members last seen in it, by PID and
// start time. A SID with a live member is never handed to a new session, so
// a pinned member still in the session proves the SID was never reused.
type sessionPin struct {
	members map[int]int64
	stop    chan struct{}
	done    chan struct{}
}

// sessionPins holds the pin of every tracked process session.
var sessionPins = struct {
	mu sync.Mutex
	m  map[sessionKey]*sessionPin
}{m: map[sessionKey]*sessionPin{}}

// pinSession starts tracking session while its leader runs. A session whose
// leader start time is unknown is never owned.
func pinSession(session OwnedSession) {
	if len(verifiedMembers(session)) == 0 {
		return
	}
	sessionPins.mu.Lock()
	pin := sessionPins.m[keyOf(session)]
	if pin == nil || pin.stop != nil {
		sessionPins.mu.Unlock()
		return
	}
	pin.stop, pin.done = make(chan struct{}), make(chan struct{})
	sessionPins.mu.Unlock()
	go observeSession(session, pin)
}

// observeSession samples membership until the recorded leader exits.
func observeSession(session OwnedSession, pin *sessionPin) {
	defer close(pin.done)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-pin.stop:
			return
		case <-ticker.C:
			if processStartedAt(session.SID) != session.StartedAt {
				return
			}
			if refreshSessionPin(session, pin) == nil {
				return
			}
			if state, err := processState(session.SID); err == nil && state == procZombie {
				return
			}
		}
	}
}

// unpinSession stops tracking session.
func unpinSession(session OwnedSession) {
	sessionPins.mu.Lock()
	defer sessionPins.mu.Unlock()
	removeSessionPin(keyOf(session))
}

// removeSessionPin requires sessionPins.mu.
func removeSessionPin(key sessionKey) {
	if pin := sessionPins.m[key]; pin != nil && pin.stop != nil {
		close(pin.stop)
	}
	delete(sessionPins.m, key)
}

func adoptSession(session OwnedSession) {
	verifiedMembers(session)
}

// ownedMember is one live process of an owned session.
type ownedMember struct {
	session OwnedSession
	pid     int
	pgid    int
	started int64
}

// ownedMembers lists the live processes of the owned sessions whose identity
// is proven, and fails closed for any other: a session is ours while its
// recorded leader runs, or while a member it was last seen with is still in
// it.
func ownedMembers(sessions []OwnedSession) []ownedMember {
	return ownedMembersWithState(sessions, processState)
}

func ownedMembersWithState(sessions []OwnedSession, readState func(int) (procState, error)) []ownedMember {
	self := syscall.Getpgrp()
	var members []ownedMember
	for _, session := range sessions {
		starts := verifiedMembers(session)
		for _, pid := range slices.Sorted(maps.Keys(starts)) {
			if state, err := readState(pid); err == nil && state == procZombie {
				continue
			}
			pgid, err := syscall.Getpgid(pid)
			if err != nil || pgid <= 1 || pgid == self {
				continue
			}
			members = append(members, ownedMember{session: session, pid: pid, pgid: pgid, started: starts[pid]})
		}
	}
	return members
}

// State reads do not establish identity; an unreaped member can still pin it.
func verifiedMembers(session OwnedSession) map[int]int64 {
	return refreshSessionPin(session, nil)
}

// refreshSessionPin lets an observer update only the pin it started with;
// an in-flight observation cannot recreate a pin removed by unpinSession.
func refreshSessionPin(session OwnedSession, expected *sessionPin) map[int]int64 {
	if session.SID <= 1 || session.StartedAt == 0 {
		return nil
	}
	pids, err := commandcancel.SessionMembers(session.SID)
	if err != nil {
		return nil
	}
	starts := map[int]int64{}
	for _, pid := range pids {
		if started := processStartedAt(pid); started != 0 {
			starts[pid] = started
		}
	}

	key := keyOf(session)
	sessionPins.mu.Lock()
	defer sessionPins.mu.Unlock()
	// The recorded leader, by PID and start time, proves itself.
	verified := starts[session.SID] == session.StartedAt
	pin, ok := sessionPins.m[key]
	if expected != nil && pin != expected {
		return nil
	}
	if !ok {
		if !verified {
			return nil
		}
		pin = &sessionPin{}
		sessionPins.m[key] = pin
	}
	for pid, started := range starts {
		if verified {
			break
		}
		verified = pin.members[pid] == started
	}
	if !verified {
		removeSessionPin(key)
		return nil
	}
	pin.members = starts
	return starts
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

func treesOf(members []ownedMember) uint32 {
	var sids []int
	for _, member := range members {
		sids = append(sids, member.session.SID)
	}
	slices.Sort(sids)
	return uint32(len(slices.Compact(sids)))
}

// sessionsOf lists the sessions that have a member, once each.
func sessionsOf(members []ownedMember) []OwnedSession {
	var sessions []OwnedSession
	for _, member := range members {
		if !slices.Contains(sessions, member.session) {
			sessions = append(sessions, member.session)
		}
	}
	return sessions
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
		stopped = map[groupKey]*stoppedGroup{}
		c.stopped[id] = stopped
	}

	var effect ProcessEffect
	var errs []error
	deadline := time.Now().Add(stopSettle)
	for {
		members := ownedMembersWithState(owned.Sessions, c.readState)
		if effect.AffectedTrees == 0 {
			effect.AffectedTrees = treesOf(members)
		}
		var running []ownedMember
		var unreadable []ownedMember
		var stateErrs []error
		for _, member := range members {
			state, err := c.readState(member.pid)
			if err != nil {
				unreadable = append(unreadable, member)
				stateErrs = append(stateErrs, fmt.Errorf("read process %d state: %w", member.pid, err))
			} else if state != procStopped && state != procZombie {
				running = append(running, member)
			}
		}
		if len(unreadable) > 0 {
			for _, member := range slices.Concat(running, unreadable) {
				effect.Survivors = append(effect.Survivors, survivorOf(member))
			}
			return effect, errors.Join(append(slices.Concat(errs, stateErrs), errProcessSurvivors)...)
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
		for _, session := range sessionsOf(running) {
			pending := map[int]bool{}
			for _, member := range running {
				if member.session == session {
					pending[member.pgid] = true
				}
			}
			signalled, err := commandcancel.SignalSessionGroups(session.SID, syscall.SIGSTOP, func(pgid int) bool { return pending[pgid] })
			if err != nil {
				errs = append(errs, err)
			}
			for _, pgid := range signalled {
				key := groupKey{session: keyOf(session), pgid: pgid}
				group := stopped[key]
				if group == nil {
					group = &stoppedGroup{members: map[int]int64{}}
					stopped[key] = group
				}
				for _, member := range members {
					if member.session == session && member.pgid == pgid {
						group.members[member.pid] = member.started
					}
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Continue sends SIGCONT to the groups a Stop suspended that are still owned
// and still the groups it suspended, and to no other group.
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
	for key, group := range stopped {
		var current []ownedMember
		pinned := false
		for _, member := range members {
			if keyOf(member.session) == key.session && member.pgid == key.pgid {
				current = append(current, member)
				pinned = pinned || group.members[member.pid] == member.started
			}
		}
		if !pinned {
			if len(current) > 0 {
				log.Warn().Str("work_session_id", id).Int("pgid", key.pgid).Msg("Left a stopped process group stopped: it is no longer the group a Stop suspended.")
			}
			continue
		}
		signalled, err := commandcancel.SignalSessionGroups(key.session.sid, syscall.SIGCONT, func(pgid int) bool { return pgid == key.pgid })
		if err != nil {
			errs = append(errs, err)
		}
		if len(signalled) > 0 {
			continued = append(continued, current...)
		}
	}
	return ProcessEffect{AffectedTrees: treesOf(continued)}, errors.Join(errs...)
}

// End cancels every owned command and terminal, then continues every owned
// group so a stopped process can act on TERM, and terminates each owned
// session with TERM and, after the grace period, KILL. Each signal is sent
// only while a pinned member still proves the session: TERM can end the
// member that pinned it, and what is left is reported, not killed. A
// session with a survivor keeps its pin, so a resent End can retry it; the
// others are not tracked afterwards.
func (c *groupProcessControl) End(id string, owned OwnedWork) (ProcessEffect, error) {
	c.mu.Lock()
	delete(c.stopped, id)
	c.mu.Unlock()
	survived := map[sessionKey]bool{}
	defer func() {
		for _, session := range owned.Sessions {
			if !survived[keyOf(session)] {
				unpinSession(session)
			}
		}
	}()

	members := ownedMembers(owned.Sessions)
	sessions := sessionsOf(members)
	var errs []error
	for _, session := range sessions {
		if _, err := commandcancel.SignalSessionGroups(session.SID, syscall.SIGCONT, nil); err != nil {
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
	for _, session := range sessions {
		wg.Go(func() {
			survivors, _, err := commandcancel.TerminateVerifiedSession(session.SID, c.grace, func() ([]int, bool) {
				starts := verifiedMembers(session)
				var live []int
				for _, pid := range slices.Sorted(maps.Keys(starts)) {
					if state, err := processState(pid); err != nil || state != procZombie {
						live = append(live, pid)
					}
				}
				return live, starts != nil
			})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			}
			survived[keyOf(session)] = len(survivors) > 0
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
