//go:build linux

package exposure

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// sshdCandidates are the only places the sshd binary is looked for. It is
// never looked up on PATH.
var sshdCandidates = []string{"/usr/sbin/sshd", "/usr/bin/sshd"}

// sshdRun is the outcome of one sshd -T run. out is the capped stdout of a
// successful run and is parsed in place; it is never logged or sent.
type sshdRun struct {
	notInstalled bool
	ok           bool
	out          []byte
}

// commandContext builds the sshd -T command; tests replace it to record what
// would run and to stand in for sshd.
var commandContext = exec.CommandContext

// findSSHD returns the first candidate under root that is a root-owned
// regular file with no group or world write bits, in a root-owned directory
// with the same mode restriction. missing is set when no candidate exists at all.
func findSSHD(root string, mapOwner func(string, uint32) uint32) (string, bool) {
	missing := true
	for _, c := range sshdCandidates {
		fi, err := os.Lstat(filepath.Join(root, c))
		if err != nil {
			continue
		}
		missing = false
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !fi.Mode().IsRegular() || !ok || mapOwner(c, st.Uid) != 0 || fi.Mode().Perm()&0o022 != 0 {
			continue
		}
		parent := filepath.Dir(c)
		dir, err := os.Lstat(filepath.Join(root, parent))
		if err != nil || !dir.IsDir() || dir.Mode().Perm()&0o022 != 0 {
			continue
		}
		dst, ok := dir.Sys().(*syscall.Stat_t)
		if !ok || mapOwner(parent, dst.Uid) != 0 {
			continue
		}
		return filepath.Join(root, c), false
	}
	return "", missing
}

// runSSHDT runs "sshd -T" directly, without a shell, with a 5-second
// deadline, stderr discarded and stdout capped. On a timeout or an overlong
// output the process is killed through its handle and reaped.
func runSSHDT(ctx context.Context, root string, mapOwner func(string, uint32) uint32) sshdRun {
	bin, missing := findSSHD(root, mapOwner)
	if bin == "" {
		return sshdRun{notInstalled: missing}
	}
	ctx, cancel := context.WithTimeout(ctx, sshdTimeout)
	defer cancel()

	cmd := commandContext(ctx, bin, "-T")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.Stdin = nil
	cmd.Stderr = nil // the null device
	cmd.WaitDelay = time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return sshdRun{}
	}
	if err := cmd.Start(); err != nil {
		return sshdRun{}
	}
	var buf bytes.Buffer
	if st, err := stdout.(*os.File).Stat(); err == nil {
		buf.Grow(int(max(0, min(st.Size(), int64(sshdStdoutCap+1)))))
	}
	_, readErr := io.Copy(&buf, io.LimitReader(stdout, sshdStdoutCap+1))
	over := buf.Len() > sshdStdoutCap
	if over {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if over || readErr != nil || waitErr != nil || ctx.Err() != nil {
		clear(buf.Bytes())
		return sshdRun{}
	}
	return sshdRun{ok: true, out: buf.Bytes()}
}

// sshdMaster is a running sshd listener: an sshd whose parent is not sshd.
type sshdMaster struct {
	args  sshdArgs
	start time.Time
}

const clockTicks = 100 // USER_HZ on every Linux architecture alpamon ships for

// findSSHDMasters scans procRoot for sshd listener masters. ok is false when
// the process table could not be read.
func findSSHDMasters(procRoot string) ([]sshdMaster, bool) {
	statData, err := readProcFile(filepath.Join(procRoot, "stat"))
	if err != nil {
		return nil, false
	}
	btime, ok := parseBootTime(statData)
	if !ok {
		return nil, false
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, false
	}
	stats := map[int]procStat{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		data, err := readProcFile(filepath.Join(procRoot, e.Name(), "stat"))
		if err != nil {
			continue // the process exited
		}
		if ps, ok := parseProcStat(data); ok {
			stats[pid] = ps
		}
	}
	var masters []sshdMaster
	for pid, ps := range stats {
		if ps.comm != "sshd" || stats[ps.ppid].comm == "sshd" {
			continue
		}
		status, err := readProcFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			return nil, false
		}
		root := false
		for line := range strings.SplitSeq(string(status), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == "Uid:" {
				root = fields[1] == "0" && fields[2] == "0"
				break
			}
		}
		if !root {
			continue
		}
		raw, err := readProcFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			return nil, false
		}
		argv := splitCmdline(raw)
		clear(raw)
		masters = append(masters, sshdMaster{
			args:  masterArgs(argv),
			start: time.Unix(btime+int64(ps.startTick/clockTicks), int64(ps.startTick%clockTicks)*int64(time.Second/clockTicks)),
		})
	}
	return masters, true
}

// masterArgs reads a master's arguments. A listener rewrites its command
// line to "sshd: <original argv> [listener] ..."; the original arguments
// are taken from that title. A title in any other form is not trusted.
func masterArgs(argv []string) sshdArgs {
	if len(argv) == 1 && strings.Contains(argv[0], " ") {
		title, ok := strings.CutPrefix(argv[0], "sshd: ")
		orig, _, found := strings.Cut(title, " [listener]")
		if !ok || !found {
			return sshdArgs{hasOverride: true}
		}
		return parseSSHDArgs(strings.Fields(orig))
	}
	return parseSSHDArgs(argv)
}

func splitCmdline(raw []byte) []string {
	raw = bytes.TrimRight(raw, "\x00")
	if len(raw) == 0 {
		return nil
	}
	var out []string
	for a := range bytes.SplitSeq(raw, []byte{0}) {
		out = append(out, string(a))
	}
	return out
}

// readProcFile reads a procfs file without following a final symlink, at
// most 64 KiB.
func readProcFile(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, 64<<10))
}
