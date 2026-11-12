package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/utils"
)

type linuxAccountLocker struct {
	handler   *UserHandler
	store     lockStateStore
	readFile  func(string) ([]byte, error)
	systemd   func() bool
	terminate func(context.Context, uint64, func(context.Context, []string) error) (int, error)
}

func newAccountLocker(h *UserHandler) accountLocker {
	return &linuxAccountLocker{
		handler:   h,
		store:     lockStateStore{path: filepath.Join(utils.DataDir(), "user-locks.json"), owner: 0},
		readFile:  os.ReadFile,
		systemd:   func() bool { info, err := os.Stat("/run/systemd/system"); return err == nil && info.IsDir() },
		terminate: terminateAccountProcesses,
	}
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
	if data.Username == "root" || uid == 0 || uid < l.uidMin() {
		return "", fmt.Errorf("refused_system_account: %q has protected uid %d", data.Username, uid)
	}
	if data.UID != nil && *data.UID != uid {
		return "", fmt.Errorf("uid_mismatch: %q has uid %d, expected %d", data.Username, uid, *data.UID)
	}
	states, err := l.store.load()
	if err != nil {
		return "", fmt.Errorf("lock_state_failed: %w", err)
	}
	state, found := states[data.Username]
	if found && state.UID != uid {
		return "", fmt.Errorf("uid_mismatch: saved lock belongs to uid %d, current uid is %d", state.UID, uid)
	}
	if cmd == common.UnlockUser.String() {
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
		states[name] = state
		// Persist the original password state before -L, including when -L
		// succeeds but a later step fails or the agent exits.
		if err := l.store.save(states); err != nil {
			return "", fmt.Errorf("lock_state_failed: %w", err)
		}
	}
	if err := l.runForAccount(ctx, name, state.UID, "/usr/sbin/usermod", "-L", "--", name); err != nil {
		return "", err
	}
	if err := l.runForAccount(ctx, name, state.UID, "/usr/sbin/usermod", "-e", "1", "--", name); err != nil {
		return "", err
	}
	if state.Linger {
		if err := l.runForAccount(ctx, name, state.UID, "/usr/bin/loginctl", "disable-linger", "--", strconv.FormatUint(state.UID, 10)); err != nil {
			return "", err
		}
	}
	var terminateSessions func(context.Context, []string) error
	if l.systemd() {
		terminateSessions = func(ctx context.Context, units []string) error {
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
		if state.Linger {
			if err := l.runForAccount(ctx, name, state.UID, "/usr/bin/loginctl", "enable-linger", "--", strconv.FormatUint(state.UID, 10)); err != nil {
				return "", err
			}
		}
		delete(states, name)
		if err := l.store.save(states); err != nil {
			return "", fmt.Errorf("lock_state_failed: %w", err)
		}
	}
	result, err := json.Marshal(struct {
		Username        string `json:"username"`
		Locked          bool   `json:"locked"`
		AlreadyUnlocked bool   `json:"already_unlocked"`
	}{name, false, !found})
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
	_, terminateErr := l.run(ctx, "/usr/bin/loginctl", "terminate-user", "--", strconv.FormatUint(uid, 10))
	if terminateErr == nil {
		return nil
	}
	// logind forgets a user after its final session and linger are removed.
	// Verify absence rather than matching localized error messages.
	output, err := l.run(ctx, "/usr/bin/loginctl", "list-users", "--no-legend", "--no-pager")
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

func (l *linuxAccountLocker) stopServices(ctx context.Context, name string, uid uint64, units []string) error {
	for _, unit := range units {
		owner, err := l.run(ctx, "/usr/bin/systemctl", "show", "--property=User", "--value", "--", unit)
		if err != nil {
			return err
		}
		owner = strings.TrimSpace(owner)
		// Shared root services can contain user sessions. Only stop the unit
		// itself when its configured execution identity is this account.
		if owner != name && owner != strconv.FormatUint(uid, 10) {
			continue
		}
		if err := l.runForAccount(ctx, name, uid, "/usr/bin/systemctl", "stop", "--no-block", "--", unit); err != nil {
			return err
		}
	}
	return nil
}

func (l *linuxAccountLocker) uidMin() uint64 {
	data, err := l.readFile("/etc/login.defs")
	if err != nil {
		return 1000
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) >= 2 && fields[0] == "UID_MIN" {
			uid, err := strconv.ParseUint(fields[1], 10, 32)
			if err == nil && uid > 0 {
				return uid
			}
			return 1000
		}
	}
	return 1000
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
		state.PasswordLocked = strings.HasPrefix(fields[1], "!") || strings.HasPrefix(fields[1], "*")
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
	if l.systemd() {
		_, err := l.readFile(filepath.Join("/var/lib/systemd/linger", name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return state, fmt.Errorf("account_state_failed: cannot read lingering: %w", err)
		}
		state.Linger = err == nil
	}
	return state, nil
}
