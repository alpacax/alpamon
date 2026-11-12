package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

const unitWorkTimeout = 60 * time.Second

var errUserNotFound = errors.New("user_not_found")

type linuxAccountLocker struct {
	toolsResolved       bool
	handler             *UserHandler
	store               lockStateStore
	files               lockFiles
	readFile            func(string) ([]byte, error)
	systemd             func() bool
	stat                func(string) (os.FileInfo, error)
	lookupUID           func(string) (*user.User, error)
	pidfdOpen           func(int, int) (int, error)
	loginctl, systemctl string
	terminate           func(context.Context, uint64, func(context.Context) error) (int, error)
}

func newAccountLocker(h *UserHandler) accountLocker {
	l := &linuxAccountLocker{
		handler:   h,
		files:     lockFiles{markerDir: "/var/lib/alpamon/user-locks.d", unitDirs: []string{"/run/systemd/system", "/etc/systemd/system"}},
		store:     lockStateStore{path: filepath.Join(utils.DataDir(), "user-locks.json"), owner: 0},
		readFile:  os.ReadFile,
		stat:      os.Stat,
		lookupUID: user.LookupId,
		pidfdOpen: unix.PidfdOpen,
		terminate: terminateAccountProcesses,
	}
	l.systemd = func() bool { _, err := l.stat("/run/systemd/system"); return err == nil }
	return l
}

func (l *linuxAccountLocker) execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	output, err := l.change(ctx, cmd, args)
	if err != nil {
		return 1, err.Error(), nil
	}
	return 0, output, nil
}

func (l *linuxAccountLocker) change(ctx context.Context, cmd string, args *common.CommandArgs) (string, error) {
	if err := validateLockUser(args); err != nil {
		return "", err
	}
	data := lockUserDataFromArgs(args)
	account, exists, err := common.UserExists(l.handler.lookupUser, data.Username)
	if err != nil {
		return "", fmt.Errorf("user_lookup_failed: %w", err)
	}
	if !exists {
		return "", fmt.Errorf("%w: %q does not exist", errUserNotFound, data.Username)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return "", fmt.Errorf("user_lookup_failed: invalid account uid")
	}
	minUID, maxUID := l.uidBounds()
	if isProtectedAccount(data.Username, uid) || uid < minUID || uid > maxUID {
		return "", fmt.Errorf("refused_system_account: %q has protected uid %d", data.Username, uid)
	}
	if *data.UID != uid {
		return "", fmt.Errorf("uid_mismatch: %q has uid %d, expected %d", data.Username, uid, *data.UID)
	}
	if cmd == common.LockUser.String() {
		if err := probeProcessHandles(l.pidfdOpen); err != nil {
			return "", err
		}
	}
	if !l.toolsResolved {
		if l.systemd() {
			loginctl, err := l.resolveTool("loginctl")
			if err != nil {
				return "", err
			}
			systemctl, err := l.resolveTool("systemctl")
			if err != nil {
				return "", err
			}
			l.loginctl, l.systemctl = loginctl, systemctl
		}
		l.toolsResolved = true
	}

	states, stateErr := l.store.load()
	if stateErr != nil && cmd == common.UnlockUser.String() {
		return "", fmt.Errorf("lock_state_failed: %w", stateErr)
	}
	state, found := states[data.Username]
	stale := found && state.UID != uid && !state.CleanupPending
	if stale {
		_, lookupErr := l.lookupUID(strconv.FormatUint(state.UID, 10))
		var absent user.UnknownUserIdError
		if !errors.As(lookupErr, &absent) {
			if lookupErr != nil {
				return "", fmt.Errorf("user_lookup_failed: %w", lookupErr)
			}
			return "", fmt.Errorf("uid_mismatch: saved lock belongs to uid %d, current uid is %d", state.UID, uid)
		}
		delete(states, data.Username)
		found = false
		state = accountLockState{DropIns: state.DropIns}
	}
	if cmd == common.UnlockUser.String() {
		if !found {
			snapshot, err := l.snapshot(data.Username, uid)
			if err != nil {
				return "", err
			}
			if snapshot.StateLost || snapshot.PasswordLocked || snapshot.Expiry == "1" {
				return "", fmt.Errorf("lock_not_owned: the account is locked, but not by alpamon")
			}
		}
		if stale {
			state.UID, state.StateLost = uid, true
			found = true
		}
		return l.unlock(ctx, data.Username, states, state, found)
	}
	return l.lock(ctx, data.Username, uid, states, state, found, stateErr)
}

func (l *linuxAccountLocker) lock(ctx context.Context, name string, uid uint64, states map[string]accountLockState, state accountLockState, found bool, stateErr error) (string, error) {
	alreadyLocked := found && state.Locked
	var errs []error
	if !found || state.CleanupPending {
		previousPaths := state.DropIns
		var err error
		state, err = l.snapshot(name, uid)
		state.DropIns = previousPaths
		if err != nil {
			if errors.Is(err, errUserNotFound) {
				return "", err
			}
			state.StateLost = true
			errs = append(errs, err)
		}
	}
	save := func() {
		if stateErr != nil {
			return
		}
		states[name] = state
		if err := l.store.save(states); err != nil {
			errs = append(errs, fmt.Errorf("lock_state_failed: %w", err))
		}
	}
	if stateErr != nil {
		errs = append(errs, fmt.Errorf("lock_state_failed: %w", stateErr))
	}
	// Preserve restore data when possible, but bookkeeping cannot prevent containment.
	save()
	for _, args := range [][]string{{"-L", "--", name}, {"-e", "1", "--", name}} {
		if err := l.runForAccount(ctx, name, uid, "/usr/sbin/usermod", args...); err != nil {
			errs = append(errs, err)
			if identityErr := l.verifyUID(name, uid); identityErr != nil {
				return "", errors.Join(append(errs, identityErr)...)
			}
		}
	}
	if err := l.files.marker(name, true); err != nil {
		errs = append(errs, fmt.Errorf("lock_marker_failed: %w", err))
	}
	var units []accountUnit
	var unitErr error
	if l.systemctl != "" {
		_, err := l.readFile(filepath.Join("/var/lib/systemd/linger", name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("account_state_failed: cannot read lingering: %w", err))
		}
		if !errors.Is(err, os.ErrNotExist) {
			if err := l.runForAccount(ctx, name, uid, l.loginctl, "disable-linger", "--", strconv.FormatUint(uid, 10)); err != nil {
				errs = append(errs, err)
			} else {
				state.Linger = true
				save()
			}
		}
		unitCtx, cancelUnits := context.WithTimeout(ctx, unitWorkTimeout)
		units, unitErr = l.accountUnits(unitCtx, name, uid)
		for _, unit := range units {
			for _, trigger := range unit.triggers {
				if !slices.Contains(state.Triggers, trigger) {
					state.Triggers = append(state.Triggers, trigger)
				}
			}
		}
		if stateErr == nil && unitCtx.Err() == nil {
			unitErr = errors.Join(unitErr, l.installDropIns(unitCtx, name, units, states, &state))
		}
		_, reloadErr := l.run(unitCtx, l.systemctl, "daemon-reload")
		unitErr = errors.Join(unitErr, unitCtx.Err(), reloadErr, l.stopServices(unitCtx, name, uid, units))
		cancelUnits()
	}

	var terminateSessions func(context.Context) error
	if l.systemctl != "" {
		terminateSessions = func(ctx context.Context) error {
			return l.terminateSessions(ctx, name, uid)
		}
	}
	count, err := l.terminate(ctx, uid, terminateSessions)
	if err != nil {
		errs = append(errs, fmt.Errorf("process_termination_incomplete: %w", err))
	}
	if unitErr != nil {
		errs = append(errs, fmt.Errorf("unit_block_failed: %w", unitErr))
	}
	state.Locked = len(errs) == 0
	save()
	if err := errors.Join(errs...); err != nil {
		return "", err
	}
	result, err := json.Marshal(struct {
		Username       string `json:"username"`
		Locked         bool   `json:"locked"`
		AlreadyLocked  bool   `json:"already_locked"`
		ProcessesEnded int    `json:"processes_ended"`
	}{name, true, alreadyLocked, count})
	return string(result), err
}

func (l *linuxAccountLocker) unlock(ctx context.Context, name string, states map[string]accountLockState, state accountLockState, found bool) (string, error) {
	alreadyUnlocked := !found || state.CleanupPending
	if found && state.StateLost && !state.CleanupPending {
		snapshot, err := l.snapshot(name, state.UID)
		if err != nil {
			return "", err
		}
		if snapshot.StateLost || snapshot.PasswordLocked || snapshot.Expiry == "1" {
			return "", missingLockState()
		}
		alreadyUnlocked = true
	}
	if !found {
		paths, err := l.files.findDropIns(name)
		if err != nil {
			return "", fmt.Errorf("lock_cleanup_failed: %w", err)
		}
		state.DropIns = paths
		state.CleanupPending = true
	}
	if !alreadyUnlocked {
		if !state.PasswordLocked {
			if err := l.runForAccount(ctx, name, state.UID, "/usr/sbin/usermod", "-U", "--", name); err != nil {
				return "", err
			}
		}
		expiry := state.Expiry
		if expiry == "" {
			expiry = "-1"
		}
		if err := l.runForAccount(ctx, name, state.UID, "/usr/sbin/usermod", "-e", expiry, "--", name); err != nil {
			return "", err
		}
	}
	removed, left, cleanupErr := l.cleanup(name, states, state)
	var triggersLeft []string
	if l.systemctl != "" {
		if _, err := l.run(ctx, l.systemctl, "daemon-reload"); err != nil {
			log.Warn().Err(err).Str("username", name).Msg("Failed to reload units after account unlock")
		}
		if !state.CleanupPending {
			triggersLeft = l.stoppedTriggers(ctx, state.Triggers)
		}
	}
	if cleanupErr != nil {
		return "", cleanupErr
	}
	if found {
		removed = nil
	}
	result, err := json.Marshal(struct {
		DropInsRemoved      []string `json:"drop_ins_removed,omitempty"`
		TriggersLeftStopped []string `json:"triggers_left_stopped,omitempty"`
		DropInsLeft         []string `json:"drop_ins_left,omitempty"`
		Username            string   `json:"username"`
		Locked              bool     `json:"locked"`
		AlreadyUnlocked     bool     `json:"already_unlocked"`
		LingerLeftDisabled  bool     `json:"linger_left_disabled,omitempty"`
	}{removed, triggersLeft, left, name, false, alreadyUnlocked, found && !alreadyUnlocked && state.Linger})
	return string(result), err
}

func (l *linuxAccountLocker) verifyUID(name string, uid uint64) error {
	account, found, err := common.UserExists(l.handler.lookupUser, name)
	if err != nil {
		return fmt.Errorf("user_lookup_failed: %w", err)
	}
	if !found {
		return fmt.Errorf("%w: %q does not exist", errUserNotFound, name)
	}
	current, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || current != uid {
		return fmt.Errorf("uid_mismatch: account identity changed before mutation")
	}
	return nil
}

func (l *linuxAccountLocker) runForAccount(ctx context.Context, name string, uid uint64, path string, args ...string) error {
	if err := l.verifyUID(name, uid); err != nil {
		return err
	}
	_, err := l.run(ctx, path, args...)
	if path == "/usr/sbin/usermod" {
		if identityErr := l.verifyUID(name, uid); identityErr != nil {
			return identityErr
		}
	}
	return err
}

func (l *linuxAccountLocker) run(ctx context.Context, path string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	code, output, err := l.handler.Executor.Run(ctx, path, args...)
	if code != 0 || err != nil {
		return "", fmt.Errorf("account_command_failed: %s exited %d: %s (%v)", filepath.Base(path), code, strings.TrimSpace(output), err)
	}
	return output, nil
}

func (l *linuxAccountLocker) terminateSessions(ctx context.Context, name string, uid uint64) error {
	if err := l.verifyUID(name, uid); err != nil {
		return err
	}
	_, terminateErr := l.run(ctx, l.loginctl, "terminate-user", "--", strconv.FormatUint(uid, 10))
	if terminateErr == nil {
		return nil
	}
	// logind forgets a user after its final session and linger are removed.
	// Verify absence rather than matching localized error messages.
	output, err := l.run(ctx, l.loginctl, "list-users", "--no-legend", "--no-pager")
	if err != nil {
		return errors.Join(terminateErr, err)
	}
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		listedUID, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil || listedUID == uid {
			return terminateErr
		}
	}
	return nil
}

func (l *linuxAccountLocker) resolveTool(name string) (string, error) {
	for _, dir := range []string{"/usr/bin", "/bin"} {
		path := filepath.Join(dir, name)
		info, err := l.stat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("missing_tool: %s", name)
}

func (l *linuxAccountLocker) forget(name string) error {
	states, err := l.store.load()
	if err != nil {
		return err
	}
	state, found := states[name]
	if !found {
		return nil
	}
	_, left, err := l.cleanup(name, states, state)
	if len(left) > 0 {
		err = errors.Join(err, fmt.Errorf("lock_cleanup_failed: drop-ins remain: %v", left))
	}
	return err
}

func (l *linuxAccountLocker) cleanup(name string, states map[string]accountLockState, state accountLockState) (removed, left []string, err error) {
	paths := state.DropIns
	// A retry must only remove artifacts, never restore a deleted account's shadow data.
	state = accountLockState{UID: state.UID, CleanupPending: true, MarkerPending: true, DropIns: paths}
	states[name] = state
	if err := l.store.save(states); err != nil {
		return nil, paths, fmt.Errorf("lock_state_failed: %w", err)
	}
	var errs []error
	if err := l.files.marker(name, false); err != nil {
		errs = append(errs, fmt.Errorf("lock_marker_failed: %w", err))
	} else {
		state.MarkerPending = false
	}
	for _, path := range paths {
		_, statErr := os.Lstat(path)
		if err := l.files.removeDropIn(path); err != nil {
			left = append(left, path)
		} else if statErr == nil {
			removed = append(removed, path)
		}
	}
	state.DropIns = left
	if state.MarkerPending || len(left) > 0 {
		states[name] = state
	} else {
		delete(states, name)
	}
	if err := l.store.save(states); err != nil {
		errs = append(errs, fmt.Errorf("lock_state_failed: %w", err))
	}
	return removed, left, errors.Join(errs...)
}

func missingLockState() error {
	return fmt.Errorf("lock_state_missing: the account is locked but its original state is unknown")
}

func isProtectedAccount(name string, uid uint64) bool {
	return name == "root" || name == "nobody" || name == "nfsnobody" || uid == 0 || uid == 65534 || uid == 4294967294
}

func (l *linuxAccountLocker) uidBounds() (uint64, uint64) {
	minUID, maxUID := uint64(1000), uint64(60000)
	data, err := l.readFile("/etc/login.defs")
	if err != nil {
		return minUID, maxUID
	}
	seen := make(map[string]bool)
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) < 2 || seen[fields[0]] {
			continue
		}
		key := fields[0]
		if key != "UID_MIN" && key != "UID_MAX" {
			continue
		}
		seen[key] = true
		uid, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil || uid == 0 {
			continue
		}
		if key == "UID_MIN" {
			minUID = uid
		} else {
			maxUID = uid
		}
	}
	return minUID, maxUID
}

func (l *linuxAccountLocker) snapshot(name string, uid uint64) (accountLockState, error) {
	state := accountLockState{UID: uid}
	data, err := l.readFile("/etc/shadow")
	if err != nil {
		return state, fmt.Errorf("account_state_failed: cannot read shadow: %w", err)
	}
	found := false
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 9 || fields[0] != name {
			continue
		}
		state.PasswordLocked = strings.HasPrefix(fields[1], "!")
		state.Expiry = fields[7]
		if state.Expiry != "" {
			if _, err := strconv.ParseUint(state.Expiry, 10, 32); err != nil {
				return state, fmt.Errorf("account_state_failed: invalid shadow expiry")
			}
		}
		found = true
		break
	}
	if !found {
		return state, fmt.Errorf("%w: no local shadow entry for %q", errUserNotFound, name)
	}
	if state.PasswordLocked && state.Expiry == "1" {
		// The pre-lock password and expiry cannot be recovered from this snapshot.
		state = accountLockState{UID: uid, StateLost: true}
	}
	return state, nil
}
