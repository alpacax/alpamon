package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type accountLockState struct {
	UID            uint64   `json:"uid"`
	Expiry         string   `json:"expiry"`
	PasswordLocked bool     `json:"password_locked"`
	Linger         bool     `json:"linger"`
	Locked         bool     `json:"locked"`
	StateLost      bool     `json:"state_lost,omitempty"`
	Triggers       []string `json:"triggers,omitempty"`
	DropIns        []string `json:"drop_ins,omitempty"`
}

type lockStateStore struct {
	path  string
	owner uint32
}

func (s lockStateStore) checkDirectory() error {
	info, err := os.Lstat(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != s.owner || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("state directory must be owned by root and not writable by group or others")
	}
	return nil
}

func (s lockStateStore) load() (map[string]accountLockState, error) {
	states := make(map[string]accountLockState)
	if err := s.checkDirectory(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return states, nil
		}
		return nil, err
	}
	fd, err := unix.Open(s.path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return states, nil
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), s.path)
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != s.owner {
		return nil, fmt.Errorf("state file must be a root-owned regular file with mode 0600")
	}
	decoder := json.NewDecoder(io.LimitReader(f, 1024*1024))
	if err := decoder.Decode(&states); err != nil {
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return s.quarantine()
		}
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return s.quarantine()
	}
	if states == nil {
		states = make(map[string]accountLockState)
	}
	return states, nil
}

func (s lockStateStore) save(states map[string]accountLockState) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	if err := s.checkDirectory(); err != nil {
		return err
	}
	data, err := json.Marshal(states)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".user-locks-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), s.path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func (s lockStateStore) quarantine() (map[string]accountLockState, error) {
	if err := os.Rename(s.path, fmt.Sprintf("%s.corrupt-%d", s.path, time.Now().Unix())); err != nil {
		return nil, err
	}
	return make(map[string]accountLockState), nil
}
