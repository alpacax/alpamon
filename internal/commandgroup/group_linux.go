package commandgroup

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type groupKey struct{}

const prefix = "alpamon-command-"

func Owned(group string) bool {
	parent := Path(os.Getpid())
	if group == "" || parent == "" {
		return false
	}
	relative, err := filepath.Rel(parent, group)
	return err == nil && strings.HasPrefix(relative, prefix)
}

func RealUID(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return ""
}

// Keep populated directories for a later removal attempt. Membership remains
// recognizable even after the tracking entry is retired.
var retired sync.Map

func retire(dir string) {
	if err := os.Remove(dir); errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.ENOTEMPTY) {
		retired.Store(dir, struct{}{})
	}
}

func Unsupported(cmd *exec.Cmd, err error) bool {
	if err == nil || cmd.SysProcAttr == nil || !cmd.SysProcAttr.UseCgroupFD {
		return false
	}
	var startErr *os.PathError
	if !errors.As(err, &startErr) || startErr.Op != "fork/exec" {
		return false
	}
	if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EPERM) {
		cmd.SysProcAttr.UseCgroupFD = false
		cmd.SysProcAttr.CgroupFD = 0
		return true
	}
	return false
}

// Path reads the unified hierarchy from the agent's cgroup namespace.
func Path(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok && filepath.IsAbs(path) && filepath.Clean(path) == path {
			return path
		}
	}
	return ""
}

// Prepare creates a private child in the agent's delegated hierarchy.
func Prepare(ctx context.Context) (context.Context, string, func()) {
	parent := Path(os.Getpid())
	if parent == "" {
		return ctx, "", func() {}
	}
	base := filepath.Join("/sys/fs/cgroup", parent)
	if _, err := os.Stat(filepath.Join(base, "cgroup.controllers")); err != nil {
		return ctx, "", func() {}
	}
	retired.Range(func(key, value any) bool {
		if err := os.Remove(key.(string)); err == nil || os.IsNotExist(err) {
			retired.Delete(key)
		}
		return true
	})
	dir, err := os.MkdirTemp(base, prefix)
	if err != nil {
		return ctx, "", func() {}
	}
	file, err := os.Open(dir)
	if err != nil {
		_ = os.Remove(dir)
		return ctx, "", func() {}
	}
	return context.WithValue(ctx, groupKey{}, file), filepath.Join(parent, filepath.Base(dir)), func() { _ = file.Close(); retire(dir) }
}

func Configure(ctx context.Context, cmd *exec.Cmd) {
	if file, ok := ctx.Value(groupKey{}).(*os.File); ok {
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = int(file.Fd())
	}
}
