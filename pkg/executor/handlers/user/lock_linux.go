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
	"golang.org/x/sys/unix"
)

type linuxAccountLocker struct {
	handler             *UserHandler
	store               lockStateStore
	readFile            func(string) ([]byte, error)
	systemd             func() bool
	stat                func(string) (os.FileInfo, error)
	lookupUID           func(string) (*user.User, error)
	pidfdOpen           func(int, int) (int, error)
	loginctl, systemctl string
	terminate           func(context.Context, uint64, func(context.Context, []string) error) (int, error)
}

func newAccountLocker(h *UserHandler) accountLocker {
	l := &linuxAccountLocker{
		handler:   h,
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
		return "", fmt.Errorf("user_not_found: %q does not exist", data.Username)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return "", fmt.Errorf("user_lookup_failed: invalid account uid")
	}
	if data.Username == "root" || uid == 0 || uid < l.uidBound("UID_MIN", 1000) || uid > l.uidBound("UID_MAX", 60000) || uid == 65534 || uid == 4294967294 || data.Username == "nobody" || data.Username == "nfsnobody" {
		return "", fmt.Errorf("refused_system_account: %q has protected uid %d", data.Username, uid)
	}
	if data.UID != nil && *data.UID != uid {
		return "", fmt.Errorf("uid_mismatch: %q has uid %d, expected %d", data.Username, uid, *data.UID)
	}
	if cmd == common.LockUser.String() {
		if err := probeProcessHandles(l.pidfdOpen); err != nil {
			return "", err
		}
	}
	l.loginctl, l.systemctl = "", ""
	if l.systemd() {
		l.loginctl, err = l.resolveTool("loginctl")
		if err != nil {
			return "", err
		}
		l.systemctl, err = l.resolveTool("systemctl")
		if err != nil {
			return "", err
		}
	}
	states, err := l.store.load()
	if err != nil {
		return "", fmt.Errorf("lock_state_failed: %w", err)
	}
	state, found := states[data.Username]
	stale := found && state.UID != uid
	if found && state.UID != uid {
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
		state = accountLockState{}
	}
	if cmd == common.UnlockUser.String() {
		if !found {
			snapshot, err := l.snapshot(data.Username, uid)
			if err != nil {
				return "", err
			}
			if snapshot.StateLost {
				return "", missingLockState()
			}
		}
		if stale {
			if err := l.store.save(states); err != nil {
				return "", fmt.Errorf("lock_state_failed: %w", err)
			}
		}
		return l.unlock(ctx, data.Username, states, state, found)
	}
	return l.lock(ctx, data.Username, uid, states, state, found)
}

func (l *linuxAccountLocker) lock(ctx context.Context, name string, uid uint64, states map[string]accountLockState, state accountLockState, found bool) (string, error) {
	alreadyLocked := found && state.Locked
	if !found {
		var err error
		state, err = l.snapshot(name, uid)
		if err != nil {
			return "", err
		}
	}
	var units []string
	lingerEnabled := false
	if l.systemctl != "" {
		_, err := l.readFile(filepath.Join("/var/lib/systemd/linger", name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("account_state_failed: cannot read lingering: %w", err)
		}
		lingerEnabled = err == nil
		units, err = l.accountUnits(ctx, name, uid)
		if err != nil {
			return "", err
		}
		for _, unit := range units {
			enabled, err := l.run(ctx, l.systemctl, "show", "--property=UnitFileState", "--value", "--", unit)
			if err != nil {
				return "", err
			}
			unitState := strings.TrimSpace(enabled)
			if (unitState == "enabled" || unitState == "enabled-runtime") && !slices.Contains(state.EnabledUnits, unit) {
				state.EnabledUnits = append(state.EnabledUnits, unit)
			}
		}
	}
	states[name] = state
	// Persist restore data before changing the account or disabling units.
	if err := l.store.save(states); err != nil {
		return "", fmt.Errorf("lock_state_failed: %w", err)
	}
	if err := l.runForAccount(ctx, name, state.UID, "/usr/sbin/usermod", "-L", "--", name); err != nil {
		return "", err
	}
	if err := l.runForAccount(ctx, name, state.UID, "/usr/sbin/usermod", "-e", "1", "--", name); err != nil {
		return "", err
	}
	if lingerEnabled {
		if err := l.runForAccount(ctx, name, state.UID, l.loginctl, "disable-linger", "--", strconv.FormatUint(state.UID, 10)); err != nil {
			return "", err
		}
		state.Linger = true
		states[name] = state
		if err := l.store.save(states); err != nil {
			return "", fmt.Errorf("lock_state_failed: %w", err)
		}
	}
	var terminateSessions func(context.Context, []string) error
	if l.systemctl != "" {
		terminateSessions = func(ctx context.Context, _ []string) error {
			serviceErr := l.stopServices(ctx, name, uid, units)
			sessionErr := l.terminateSessions(ctx, name, uid)
			return errors.Join(serviceErr, sessionErr)
		}
	}
	count, err := l.terminate(ctx, uid, terminateSessions)
	if err != nil {
		return "", fmt.Errorf("process_termination_incomplete: %w", err)
	}
	state.Locked = true
	states[name] = state
	if err := l.store.save(states); err != nil {
		return "", fmt.Errorf("lock_state_failed: %w", err)
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
	if found && state.StateLost {
		return "", missingLockState()
	}
	if found {
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
		if l.systemctl != "" {
			for _, unit := range state.EnabledUnits {
				if err := l.runForAccount(ctx, name, state.UID, l.systemctl, "enable", "--", unit); err != nil {
					return "", err
				}
			}
		}
		delete(states, name)
		if err := l.store.save(states); err != nil {
			return "", fmt.Errorf("lock_state_failed: %w", err)
		}
	}
	result, err := json.Marshal(struct {
		Username           string `json:"username"`
		Locked             bool   `json:"locked"`
		AlreadyUnlocked    bool   `json:"already_unlocked"`
		LingerLeftDisabled bool   `json:"linger_left_disabled,omitempty"`
	}{name, false, !found, found && state.Linger})
	return string(result), err
}

func (l *linuxAccountLocker) verifyUID(name string, uid uint64) error {
	account, found, err := common.UserExists(l.handler.lookupUser, name)
	if err != nil {
		return fmt.Errorf("user_lookup_failed: %w", err)
	}
	if !found {
		return fmt.Errorf("user_not_found: %q does not exist", name)
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

func (l *linuxAccountLocker) accountUnits(ctx context.Context, name string, uid uint64) ([]string, error) {
	output, err := l.run(ctx, l.systemctl, "list-units", "--all", "--type=service,timer,socket,path", "--no-legend", "--no-pager", "--plain")
	if err != nil {
		return nil, err
	}
	var units []string
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		unit := fields[0]
		services := []string{unit}
		if !strings.HasSuffix(unit, ".service") {
			triggers, err := l.run(ctx, l.systemctl, "show", "--property=Triggers", "--value", "--", unit)
			if err != nil {
				return nil, err
			}
			services = strings.Fields(triggers)
		}
		for _, service := range services {
			if !strings.HasSuffix(service, ".service") {
				continue
			}
			owner, err := l.run(ctx, l.systemctl, "show", "--property=User", "--value", "--", service)
			if err != nil {
				return nil, err
			}
			owner = strings.TrimSpace(owner)
			if owner == name || owner == strconv.FormatUint(uid, 10) {
				if !slices.Contains(units, unit) {
					units = append(units, unit)
				}
				break
			}
		}
	}
	return units, nil
}

func (l *linuxAccountLocker) stopServices(ctx context.Context, name string, uid uint64, units []string) error {
	for _, unit := range units {
		// Queue the stop before killing frozen tasks so systemd suppresses restarts.
		if err := l.runForAccount(ctx, name, uid, l.systemctl, "stop", "--no-block", "--job-mode=ignore-dependencies", "--", unit); err != nil {
			return err
		}
		if err := l.runForAccount(ctx, name, uid, l.systemctl, "disable", "--", unit); err != nil {
			return err
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
	if _, found := states[name]; !found {
		return nil
	}
	delete(states, name)
	return l.store.save(states)
}

func missingLockState() error {
	return fmt.Errorf("lock_state_missing: the account is locked but its original state is unknown")
}

func (l *linuxAccountLocker) uidBound(key string, fallback uint64) uint64 {
	data, err := l.readFile("/etc/login.defs")
	if err != nil {
		return fallback
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) >= 2 && fields[0] == key {
			uid, err := strconv.ParseUint(fields[1], 10, 32)
			if err == nil && uid > 0 {
				return uid
			}
			return fallback
		}
	}
	return fallback
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
		return state, fmt.Errorf("user_not_found: no local shadow entry for %q", name)
	}
	if state.PasswordLocked && state.Expiry == "1" {
		// The pre-lock password and expiry cannot be recovered from this snapshot.
		state = accountLockState{UID: uid, StateLost: true}
	}
	return state, nil
}
