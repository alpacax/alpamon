//go:build !windows

package utils

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// pamModuleName is the file the alpamon-pam packages install and the
	// session hook line loads, by bare name (deb) or absolute path (rpm).
	pamModuleName = "pam_alpamon.so"
	// pamMaxIncludeDepth is libpam's own limit (PAM_SUBSTACK_MAX_LEVEL):
	// deeper includes fail there, so they cannot carry the hook.
	pamMaxIncludeDepth = 16
	// pamMaxFilesPerService bounds the work for one service on a host with a
	// large include tree. Real stacks visit fewer than ten files.
	pamMaxFilesPerService = 64
	// pamMaxFileSize is far above any real PAM file; a larger one is not read.
	pamMaxFileSize = 256 << 10
	// pamFileCacheMax bounds the parsed-file cache; it is cleared when full.
	pamFileCacheMax = 256

	// A successful sshd -T answer is reused until sshd's binary or config
	// files change, and re-checked after sshdUsePAMMaxAge regardless, for
	// config pulled in from outside the files fingerprinted here. A failed
	// check is retried after sshdUsePAMRetryAfter rather than on every report.
	sshdUsePAMMaxAge     = 24 * time.Hour
	sshdUsePAMRetryAfter = time.Hour

	// loginCaptureWarnAfter is how many consecutive failed checks it takes
	// to log one WARN for the life of the process.
	loginCaptureWarnAfter = 3
)

// pamConfigDirs is the order libpam searches for a service's file and for a
// relative include: /etc/pam.d, then the distribution's copies. /usr/etc/pam.d
// is the vendor directory some SUSE releases build libpam with.
var pamConfigDirs = []string{"/etc/pam.d", "/usr/lib/pam.d", "/usr/etc/pam.d"}

// pamModuleDirs are the directories libpam resolves a bare module name
// against, by distribution: rpm-based in lib64, Debian-family in the multiarch
// directories (x86_64-linux-gnu, arm-linux-gnueabihf, ...) found under /lib
// and /usr/lib.
var pamModuleDirs = []string{"/lib/security", "/lib64/security", "/usr/lib/security", "/usr/lib64/security"}

var pamMultiarchParents = []string{"/lib", "/usr/lib"}

// The binaries that tell an installed service from an absent one.
var (
	sshdBinaries  = []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd", "/usr/bin/sshd"}
	loginBinaries = []string{"/bin/login", "/usr/bin/login", "/sbin/login", "/usr/sbin/login"}
	suBinaries    = []string{"/bin/su", "/usr/bin/su"}
)

// The files whose change re-runs sshd -T, besides the binary itself.
// /run/sshd is there because sshd -T fails while its privilege separation
// directory is missing, as on a socket-activated sshd that has not yet taken
// a connection since boot; the check is re-run as soon as it appears.
var (
	sshdConfigFiles = []string{"/etc/ssh/sshd_config", "/usr/etc/ssh/sshd_config", "/run/sshd"}
	sshdConfigDirs  = []string{"/etc/ssh/sshd_config.d", "/usr/etc/ssh/sshd_config.d"}
)

// pamDirective is one session-relevant line of a PAM file: either a session
// module (module set) or a file to follow (include set), from a session
// include or substack line or a Debian @include.
type pamDirective struct {
	module  string
	include string
}

type pamFileEntry struct {
	modTime    time.Time
	size       int64
	directives []pamDirective
}

type sshdUsePAMEntry struct {
	checked     bool
	fingerprint string
	value       string
	at          time.Time
}

// loginCaptureCollector builds the login_capture block from a filesystem
// rooted at root, which tests point at a fixture tree.
type loginCaptureCollector struct {
	root     string
	readFile func(string) ([]byte, error)
	runSSHDT func(ctx context.Context, sshdPath string) ([]byte, error)
	now      func() time.Time

	mu       sync.Mutex
	files    map[string]pamFileEntry
	sshd     sshdUsePAMEntry
	failures int
	warned   bool
}

func newLoginCaptureCollector(root string) *loginCaptureCollector {
	return &loginCaptureCollector{
		root:     root,
		readFile: os.ReadFile,
		runSSHDT: runSSHDT,
		now:      time.Now,
		files:    make(map[string]pamFileEntry),
	}
}

func runSSHDT(ctx context.Context, sshdPath string) ([]byte, error) {
	return exec.CommandContext(ctx, sshdPath, "-T").Output()
}

// Get returns the block, or nil when the check failed. A failure, including a
// panic, never reaches the caller: the report goes out without the block.
func (c *loginCaptureCollector) Get() (block *LoginCapture) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			block = nil
			c.recordFailure(fmt.Errorf("panic: %v", r))
		}
	}()

	block = c.collect()
	c.failures = 0
	return block
}

func (c *loginCaptureCollector) recordFailure(err error) {
	c.failures++
	log.Debug().Err(err).Msg("Login capture check failed; reporting without it.")
	if c.failures >= loginCaptureWarnAfter && !c.warned {
		c.warned = true
		// No error detail: it may carry paths, and DEBUG already has it.
		log.Warn().Int("attempts", c.failures).Msg("Login capture check keeps failing; reports go out without it.")
	}
}

func (c *loginCaptureCollector) collect() *LoginCapture {
	var modules []string
	block := &LoginCapture{Schema: loginCaptureSchema}
	block.Hooks.SSHD = c.hookStatus("sshd", sshdBinaries, &modules)
	block.Hooks.Login = c.hookStatus("login", loginBinaries, &modules)
	block.Hooks.Su = c.hookStatus("su", suBinaries, &modules)
	// su-l is reported only where it has a file of its own; elsewhere su
	// serves login shells too and the server reads the absent key that way.
	if c.findPAMFile("su-l") != "" {
		block.Hooks.SuL = c.hookStatus("su-l", nil, &modules)
	}
	block.PAMModule = c.moduleStatus(modules)
	block.SSHDUsePAM = c.sshdUsePAM()
	return block
}

// hookStatus resolves service's PAM file the way libpam does and reports
// whether a session line loading the module is reachable from it, adding
// the module references it found to modules.
func (c *loginCaptureCollector) hookStatus(service string, binaries []string, modules *[]string) string {
	file := c.findPAMFile(service)
	if file == "" {
		if c.firstExisting(binaries) != "" {
			// The service is installed but no PAM file was found: either it
			// does not use PAM or it lives somewhere this check does not look.
			// Neither may read as "not applicable".
			return HookUnreadable
		}
		return HookNotApplicable
	}

	w := pamWalk{}
	c.walk(file, &w, 0, nil)
	switch {
	case w.failed:
		return HookUnreadable
	case len(w.modules) > 0:
		*modules = append(*modules, w.modules...)
		return HookRegistered
	default:
		return HookMissing
	}
}

type pamWalk struct {
	visits  int
	failed  bool
	modules []string
}

// walk collects the module's session lines reachable from file. Anything that
// keeps the stack from being known for certain (an unreadable or missing
// include, a loop, a chain deeper than libpam allows) fails the walk: libpam
// replaces a failed include with an entry that always fails, so such a stack
// cannot be reported as either registered or missing.
func (c *loginCaptureCollector) walk(file string, w *pamWalk, depth int, ancestors []string) {
	if w.failed {
		return
	}
	w.visits++
	if depth >= pamMaxIncludeDepth || w.visits > pamMaxFilesPerService || slices.Contains(ancestors, file) {
		w.failed = true
		return
	}
	directives, ok := c.loadPAMFile(file)
	if !ok {
		w.failed = true
		return
	}
	ancestors = append(slices.Clip(ancestors), file)
	for _, d := range directives {
		if d.include == "" {
			if path.Base(d.module) == pamModuleName {
				w.modules = append(w.modules, d.module)
			}
			continue
		}
		target := c.resolveInclude(d.include)
		if target == "" {
			w.failed = true
			return
		}
		c.walk(target, w, depth+1, ancestors)
		if w.failed {
			return
		}
	}
}

// findPAMFile returns the first of the config directories holding service,
// or "". A path that exists but cannot be stat'ed is returned too, so that it
// reads as unreadable instead of absent.
func (c *loginCaptureCollector) findPAMFile(service string) string {
	for _, dir := range pamConfigDirs {
		p := filepath.Join(c.root, dir, service)
		if _, err := os.Stat(p); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return p
		}
	}
	return ""
}

func (c *loginCaptureCollector) resolveInclude(name string) string {
	if !strings.HasPrefix(name, "/") {
		return c.findPAMFile(name)
	}
	p := filepath.Join(c.root, name)
	if _, err := os.Stat(p); err != nil && errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	return p
}

// loadPAMFile returns file's session directives, parsing it only when its
// mtime or size changed since the last read. Only regular files are read, so
// a FIFO planted in pam.d cannot block the report.
func (c *loginCaptureCollector) loadPAMFile(file string) ([]pamDirective, bool) {
	info, err := os.Stat(file)
	if err != nil || !info.Mode().IsRegular() || info.Size() > pamMaxFileSize {
		return nil, false
	}
	if e, ok := c.files[file]; ok && e.size == info.Size() && e.modTime.Equal(info.ModTime()) {
		return e.directives, true
	}
	data, err := c.readFile(file)
	if err != nil || len(data) > pamMaxFileSize {
		return nil, false
	}
	directives, ok := parsePAMSessionDirectives(data)
	if !ok {
		return nil, false
	}
	if len(c.files) >= pamFileCacheMax {
		clear(c.files)
	}
	c.files[file] = pamFileEntry{modTime: info.ModTime(), size: info.Size(), directives: directives}
	return directives, true
}

// parsePAMSessionDirectives reads a pam.d file the way libpam assembles its
// lines: leading blanks skipped, everything from '#' on dropped, and a line
// ending in a backslash continued on the next unless it carries a comment.
// It returns false for a file that ends inside a continued line, which libpam
// rejects as a whole.
func parsePAMSessionDirectives(data []byte) ([]pamDirective, bool) {
	var out []pamDirective
	var logical strings.Builder
	pending := false
	for raw := range strings.SplitSeq(string(data), "\n") {
		line := strings.TrimRight(raw, " \t")
		hasComment := strings.Contains(line, "#")
		continued := strings.HasSuffix(line, "\\")
		if continued {
			line = line[:len(line)-1] + " "
		}
		line = strings.TrimLeft(line, " \t")
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		logical.WriteString(line)
		if continued && !hasComment {
			pending = true
			continue
		}
		pending = false
		if d, ok := parsePAMLine(logical.String()); ok {
			out = append(out, d)
		}
		logical.Reset()
	}
	if pending {
		return nil, false
	}
	return out, true
}

func parsePAMLine(line string) (pamDirective, bool) {
	tokens := pamTokens(line, 3)
	if len(tokens) < 2 {
		return pamDirective{}, false
	}
	if tokens[0] == "@include" {
		return pamDirective{include: tokens[1]}, true
	}
	// A leading '-' only silences a module that fails to load.
	if !strings.EqualFold(strings.TrimPrefix(tokens[0], "-"), "session") || len(tokens) < 3 {
		return pamDirective{}, false
	}
	if strings.EqualFold(tokens[1], "include") || strings.EqualFold(tokens[1], "substack") {
		return pamDirective{include: tokens[2]}, true
	}
	return pamDirective{module: tokens[2]}, true
}

// pamTokens splits up to max tokens the way libpam's tokenizer does: blanks
// separate tokens, and a "[...]" control is one token up to the first
// unescaped ']'.
func pamTokens(s string, max int) []string {
	var tokens []string
	for len(tokens) < max {
		s = strings.TrimLeft(s, " \t\n")
		if s == "" {
			break
		}
		if s[0] == '[' {
			end := len(s)
			for i := 1; i < len(s); i++ {
				if s[i] == '\\' && i+1 < len(s) && s[i+1] == ']' {
					i++
					continue
				}
				if s[i] == ']' {
					end = i
					break
				}
			}
			tokens = append(tokens, s[1:end])
			s = s[min(end+1, len(s)):]
			continue
		}
		end := strings.IndexAny(s, " \t\n")
		if end < 0 {
			end = len(s)
		}
		tokens = append(tokens, s[:end])
		s = s[end:]
	}
	return tokens
}

// moduleStatus reports the module present only when every module reference
// on a registered hook resolves to an installed file; a hook naming a path
// that is not there loads nothing. With no hook registered it looks for the
// module where libpam resolves a bare name.
func (c *loginCaptureCollector) moduleStatus(refs []string) string {
	if len(refs) == 0 {
		refs = []string{pamModuleName}
	}
	slices.Sort(refs)
	for _, ref := range slices.Compact(refs) {
		if !c.moduleInstalled(ref) {
			return PAMModuleMissing
		}
	}
	return PAMModulePresent
}

func (c *loginCaptureCollector) moduleInstalled(ref string) bool {
	if strings.HasPrefix(ref, "/") {
		return c.isRegularFile(filepath.Join(c.root, ref))
	}
	for _, dir := range c.moduleDirs() {
		if c.isRegularFile(filepath.Join(dir, ref)) {
			return true
		}
	}
	return false
}

func (c *loginCaptureCollector) moduleDirs() []string {
	dirs := make([]string, 0, len(pamModuleDirs)+4)
	for _, d := range pamModuleDirs {
		dirs = append(dirs, filepath.Join(c.root, d))
	}
	for _, parent := range pamMultiarchParents {
		entries, err := os.ReadDir(filepath.Join(c.root, parent))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.Contains(e.Name(), "-linux-gnu") {
				dirs = append(dirs, filepath.Join(c.root, parent, e.Name(), "security"))
			}
		}
	}
	return dirs
}

func (c *loginCaptureCollector) isRegularFile(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Mode().IsRegular()
}

func (c *loginCaptureCollector) firstExisting(paths []string) string {
	for _, p := range paths {
		full := filepath.Join(c.root, p)
		if c.isRegularFile(full) {
			return full
		}
	}
	return ""
}

// sshdUsePAM returns sshd's effective UsePAM from sshd -T, or nil when sshd
// is not installed or the check fails. sshd -T runs again only when the
// fingerprint of sshd's binary and config files changes or the cached answer
// ages out.
func (c *loginCaptureCollector) sshdUsePAM() *string {
	sshd := c.firstExisting(sshdBinaries)
	if sshd == "" {
		c.sshd = sshdUsePAMEntry{}
		return nil
	}

	fingerprint := c.sshdFingerprint(sshd)
	now := c.now()
	maxAge := sshdUsePAMMaxAge
	if c.sshd.value == "" {
		maxAge = sshdUsePAMRetryAfter
	}
	if !c.sshd.checked || c.sshd.fingerprint != fingerprint || now.Sub(c.sshd.at) >= maxAge {
		ctx, cancel := context.WithTimeout(context.Background(), pamQueryTimeout)
		out, err := c.runSSHDT(ctx, sshd)
		cancel()
		value := ""
		if err == nil {
			value = parseSSHDUsePAM(string(out))
		}
		c.sshd = sshdUsePAMEntry{checked: true, fingerprint: fingerprint, value: value, at: now}
	}

	if c.sshd.value == "" {
		return nil
	}
	value := c.sshd.value
	return &value
}

// sshdFingerprint identifies the inputs of sshd -T by path, mtime and size:
// the binary, the main config files and every drop-in in their .d
// directories.
func (c *loginCaptureCollector) sshdFingerprint(sshd string) string {
	var b strings.Builder
	stamp := func(p string) {
		b.WriteString(p)
		if info, err := os.Stat(p); err == nil {
			b.WriteString("|" + strconv.FormatInt(info.ModTime().UnixNano(), 10) + "|" + strconv.FormatInt(info.Size(), 10))
		}
		b.WriteByte('\n')
	}
	stamp(sshd)
	for _, f := range sshdConfigFiles {
		stamp(filepath.Join(c.root, f))
	}
	for _, d := range sshdConfigDirs {
		dir := filepath.Join(c.root, d)
		stamp(dir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			stamp(filepath.Join(dir, e.Name()))
		}
	}
	return b.String()
}
