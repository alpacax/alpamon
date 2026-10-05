//go:build linux || darwin

package utils

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	// pamReferenceModule is the module every libpam installation ships. The
	// directory holding it is the one libpam resolves relative names against.
	pamReferenceModule = "pam_unix.so"
	// pamMaxIncludeDepth is libpam's own limit (PAM_SUBSTACK_MAX_LEVEL):
	// deeper includes fail there, so they cannot carry the hook.
	pamMaxIncludeDepth = 16
	// pamMaxFilesPerService bounds the work for one service on a host with a
	// large include tree. Real stacks visit fewer than ten files.
	pamMaxFilesPerService = 64
	// pamMaxFileSize is far above any real PAM or sshd config file; a larger
	// one is not read.
	pamMaxFileSize = 256 << 10
	// pamFileCacheMax bounds the parsed-file cache; it is cleared when full.
	pamFileCacheMax = 256

	// A successful sshd -T answer is reused until sshd's binary or config
	// files change, and re-checked after sshdUsePAMMaxAge regardless, for
	// config pulled in from outside the files fingerprinted here. A failed
	// check is retried after sshdUsePAMRetryAfter rather than on every report.
	sshdUsePAMMaxAge     = 24 * time.Hour
	sshdUsePAMRetryAfter = time.Hour

	// loginCaptureDeadline is how long a report waits for the check. A check
	// still running then (a hung mount under /etc or /usr/lib) is left to
	// finish on its own and the report goes out without the block.
	loginCaptureDeadline = 5 * time.Second

	// loginCaptureWarnAfter is how many consecutive failed checks it takes
	// to log one WARN for the life of the process.
	loginCaptureWarnAfter = 3

	defaultSSHDPAMService = "sshd"
)

// pamConfigDirs is the order libpam searches for a service's file and for a
// relative include: /etc/pam.d, then the distribution's copies. /usr/etc/pam.d
// is the vendor directory some SUSE releases build libpam with.
var pamConfigDirs = []string{"/etc/pam.d", "/usr/lib/pam.d", "/usr/etc/pam.d"}

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
	sshdConfigFiles = []string{"/etc/ssh/sshd_config", "/usr/etc/ssh/sshd_config"}
	sshdConfigDirs  = []string{"/etc/ssh/sshd_config.d", "/usr/etc/ssh/sshd_config.d"}
	sshdPrivsepDir  = "/run/sshd"
)

// multiarchTriplets maps a Go architecture to the Debian multiarch names its
// PAM modules are installed under.
func multiarchTriplets(goarch string) []string {
	switch goarch {
	case "amd64":
		return []string{"x86_64-linux-gnu"}
	case "arm64":
		return []string{"aarch64-linux-gnu"}
	case "386":
		return []string{"i386-linux-gnu"}
	case "arm":
		return []string{"arm-linux-gnueabihf", "arm-linux-gnueabi"}
	case "ppc64le":
		return []string{"powerpc64le-linux-gnu"}
	case "s390x":
		return []string{"s390x-linux-gnu"}
	case "riscv64":
		return []string{"riscv64-linux-gnu"}
	case "mips64le":
		return []string{"mips64el-linux-gnuabi64"}
	case "loong64":
		return []string{"loongarch64-linux-gnu"}
	}
	return nil
}

// fileStamp identifies one version of a file: a same-size rewrite that puts
// the mtime back still changes ctime, and a replaced file changes inode.
type fileStamp struct {
	modTime int64
	size    int64
	ino     uint64
	ctime   int64
}

func stampOf(info fs.FileInfo) fileStamp {
	ino, ctime := statIdentity(info)
	return fileStamp{modTime: info.ModTime().UnixNano(), size: info.Size(), ino: ino, ctime: ctime}
}

func (s fileStamp) String() string {
	return strconv.FormatInt(s.modTime, 10) + "|" + strconv.FormatInt(s.size, 10) + "|" +
		strconv.FormatUint(s.ino, 10) + "|" + strconv.FormatInt(s.ctime, 10)
}

// pamDirective is one session-relevant line of a PAM file: either a session
// module (module set) or a file to follow (include set), from a session
// include or substack line or a Debian @include.
type pamDirective struct {
	module  string
	include string
}

type pamFileEntry struct {
	stamp      fileStamp
	directives []pamDirective
}

// sshdEntry caches what sshd -T and sshd's config files say.
type sshdEntry struct {
	checked     bool
	fingerprint string
	at          time.Time
	usePAM      string // "yes", "no", or "" when undeterminable
	service     string // PAMServiceName, "sshd" when sshd -T did not say
	// matchScoped is set when a config file sets PAMServiceName inside a
	// Match block, so different connections may run different PAM stacks.
	matchScoped bool
}

type moduleDirEntry struct {
	fingerprint string
	dir         string
}

// loginCaptureCollector builds the login_capture block from a filesystem
// rooted at root, which tests point at a fixture tree.
type loginCaptureCollector struct {
	root     string
	triplets []string
	deadline time.Duration
	readFile func(string) ([]byte, error)
	runSSHDT func(ctx context.Context, sshdPath string) ([]byte, error)
	now      func() time.Time

	// mu guards the fields below it. The caches after them belong to the one
	// collection running at a time and need no lock.
	mu            sync.Mutex
	inflight      chan struct{}
	inflightSince time.Time
	last          *LoginCapture
	failures      int
	warned        bool

	files     map[string]pamFileEntry
	sshd      sshdEntry
	moduleDir moduleDirEntry
}

func newLoginCaptureCollector(root string) *loginCaptureCollector {
	return &loginCaptureCollector{
		root:     root,
		triplets: multiarchTriplets(runtime.GOARCH),
		deadline: loginCaptureDeadline,
		readFile: os.ReadFile,
		runSSHDT: runSSHDT,
		now:      time.Now,
		files:    make(map[string]pamFileEntry),
	}
}

func runSSHDT(ctx context.Context, sshdPath string) ([]byte, error) {
	return exec.CommandContext(ctx, sshdPath, "-T").Output()
}

// Get returns the block, or nil when the check failed or did not finish
// within the deadline. The check runs in its own goroutine and at most one
// runs at a time: a caller arriving while one is in flight gets the last
// result at once, or nil once the running check has outlived the deadline,
// and never starts a second one. A failure, including a panic, never reaches
// the caller.
func (c *loginCaptureCollector) Get() *LoginCapture {
	c.mu.Lock()
	if c.inflight != nil {
		stuck := time.Since(c.inflightSince) >= c.deadline
		last := c.last.clone()
		c.mu.Unlock()
		if stuck {
			return nil
		}
		return last
	}
	done := make(chan struct{})
	c.inflight, c.inflightSince = done, time.Now()
	c.mu.Unlock()

	go c.run(done)

	timer := time.NewTimer(c.deadline)
	defer timer.Stop()
	select {
	case <-done:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.last.clone()
	case <-timer.C:
		c.mu.Lock()
		defer c.mu.Unlock()
		c.recordFailureLocked(errors.New("timed out"))
		return nil
	}
}

func (c *loginCaptureCollector) run(done chan struct{}) {
	block, err := c.collectSafely()
	c.mu.Lock()
	c.last = block
	if err != nil {
		c.recordFailureLocked(err)
	} else {
		c.failures = 0
	}
	c.inflight = nil
	c.mu.Unlock()
	close(done)
}

func (c *loginCaptureCollector) collectSafely() (block *LoginCapture, err error) {
	defer func() {
		if r := recover(); r != nil {
			block, err = nil, fmt.Errorf("panic: %v", r)
		}
	}()
	return c.collect(), nil
}

func (c *loginCaptureCollector) recordFailureLocked(err error) {
	c.failures++
	log.Debug().Err(err).Msg("Login capture check failed; reporting without it.")
	if c.failures >= loginCaptureWarnAfter && !c.warned {
		c.warned = true
		// No error detail: it may carry paths, and DEBUG already has it.
		log.Warn().Int("attempts", c.failures).Msg("Login capture check keeps failing; reports go out without it.")
	}
}

func (b *LoginCapture) clone() *LoginCapture {
	if b == nil {
		return nil
	}
	out := *b
	if b.SSHDUsePAM != nil {
		v := *b.SSHDUsePAM
		out.SSHDUsePAM = &v
	}
	return &out
}

// hookResult accumulates, across services, what the module status needs.
type hookResult struct {
	anyLine  bool // some reachable session line names the module
	loadable bool // and at least one of them resolves to an installed file
}

func (c *loginCaptureCollector) collect() *LoginCapture {
	moduleDir := c.libpamModuleDir()
	sshd := c.sshdState()

	var acc hookResult
	block := &LoginCapture{Schema: loginCaptureSchema}
	block.Hooks.SSHD = c.hookStatus(sshd.service, sshdBinaries, moduleDir, &acc)
	if sshd.matchScoped {
		block.Hooks.SSHD = HookUnreadable
	}
	block.Hooks.Login = c.hookStatus("login", loginBinaries, moduleDir, &acc)
	block.Hooks.Su = c.hookStatus("su", suBinaries, moduleDir, &acc)
	// su-l is reported only where it has a file of its own; elsewhere su
	// serves login shells too and the server reads the absent key that way.
	if c.findPAMFile("su-l") != "" {
		block.Hooks.SuL = c.hookStatus("su-l", nil, moduleDir, &acc)
	}

	switch {
	case acc.loadable:
		block.PAMModule = PAMModulePresent
	case !acc.anyLine && moduleDir != "" && isRegularFile(filepath.Join(moduleDir, pamModuleName)):
		block.PAMModule = PAMModulePresent
	default:
		block.PAMModule = PAMModuleMissing
	}

	if sshd.usePAM != "" {
		value := sshd.usePAM
		block.SSHDUsePAM = &value
	}
	return block
}

// hookStatus resolves service's PAM file the way libpam does and reports
// whether a session line reachable from it loads the module: the line must
// name pam_alpamon.so and resolve, as libpam resolves it, to an installed
// file. A hook whose module is not where libpam loads it from is skipped at
// login and reads as missing.
func (c *loginCaptureCollector) hookStatus(service string, binaries []string, moduleDir string, acc *hookResult) string {
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
	if w.failed {
		return HookUnreadable
	}
	if len(w.modules) == 0 {
		return HookMissing
	}
	acc.anyLine = true
	unresolvable := false
	for _, ref := range w.modules {
		if !strings.HasPrefix(ref, "/") && moduleDir == "" {
			unresolvable = true
			continue
		}
		if c.moduleLoadable(ref, moduleDir) {
			acc.loadable = true
			return HookRegistered
		}
	}
	if unresolvable {
		// The line names the module relative to libpam's directory, which
		// could not be found on this host.
		return HookUnreadable
	}
	return HookMissing
}

// moduleLoadable reports whether libpam would find the module a hook line
// names: an absolute path as is, anything else under libpam's directory.
func (c *loginCaptureCollector) moduleLoadable(ref, moduleDir string) bool {
	if strings.HasPrefix(ref, "/") {
		return isRegularFile(filepath.Join(c.root, ref))
	}
	return isRegularFile(filepath.Join(moduleDir, ref))
}

// libpamModuleDir returns the directory libpam resolves relative module
// names against, found as the first candidate holding pam_unix.so, with
// symlinks resolved; "" when none does. The candidates are the multiarch
// directories for this architecture (Debian family), then lib64 (RHEL family,
// SUSE) and lib. The answer is cached by the stat of the candidates, so on an
// unchanged host it costs only those stats.
func (c *loginCaptureCollector) libpamModuleDir() string {
	candidates := make([]string, 0, 2*len(c.triplets)+4)
	for _, t := range c.triplets {
		candidates = append(candidates, "/lib/"+t+"/security", "/usr/lib/"+t+"/security")
	}
	candidates = append(candidates, "/lib64/security", "/usr/lib64/security", "/lib/security", "/usr/lib/security")

	var fp strings.Builder
	for _, d := range candidates {
		stampInto(&fp, filepath.Join(c.root, d))
	}
	if c.moduleDir.fingerprint == fp.String() {
		return c.moduleDir.dir
	}

	dir := ""
	for _, d := range candidates {
		full := filepath.Join(c.root, d)
		if !isRegularFile(filepath.Join(full, pamReferenceModule)) {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(full); err == nil {
			dir = resolved
		} else {
			dir = full
		}
		break
	}
	c.moduleDir = moduleDirEntry{fingerprint: fp.String(), dir: dir}
	return dir
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
			// Exact file name only: pam_alpamon_legacy.so or
			// pam_alpamon.so.bak is another module.
			if filepath.Base(d.module) == pamModuleName {
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
// stamp (mtime, size, inode, ctime) changed since the last read.
func (c *loginCaptureCollector) loadPAMFile(file string) ([]pamDirective, bool) {
	data, stamp, cached, ok := c.readSmallFile(file, c.files[file].stamp)
	if !ok {
		return nil, false
	}
	if cached {
		return c.files[file].directives, true
	}
	directives, ok := parsePAMSessionDirectives(data)
	if !ok {
		return nil, false
	}
	if len(c.files) >= pamFileCacheMax {
		clear(c.files)
	}
	c.files[file] = pamFileEntry{stamp: stamp, directives: directives}
	return directives, true
}

// readSmallFile reads file unless its stamp equals known (cached is then
// true and nothing is read). Only regular files up to pamMaxFileSize are
// read, so a FIFO or device where a config file should be cannot block.
func (c *loginCaptureCollector) readSmallFile(file string, known fileStamp) (data []byte, stamp fileStamp, cached, ok bool) {
	info, err := os.Stat(file)
	if err != nil || !info.Mode().IsRegular() || info.Size() > pamMaxFileSize {
		return nil, fileStamp{}, false, false
	}
	stamp = stampOf(info)
	if stamp == known {
		return nil, stamp, true, true
	}
	data, err = c.readFile(file)
	if err != nil || len(data) > pamMaxFileSize {
		return nil, fileStamp{}, false, false
	}
	return data, stamp, false, true
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

func isRegularFile(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Mode().IsRegular()
}

func (c *loginCaptureCollector) firstExisting(paths []string) string {
	for _, p := range paths {
		full := filepath.Join(c.root, p)
		if isRegularFile(full) {
			return full
		}
	}
	return ""
}

// sshdState returns what sshd -T and sshd's config files say: UsePAM, the
// PAM service sshd opens sessions under, and whether that service is chosen
// per connection. sshd -T runs again only when the fingerprint of sshd's
// binary and config files changes or the cached answer ages out.
func (c *loginCaptureCollector) sshdState() sshdEntry {
	sshd := c.firstExisting(sshdBinaries)
	if sshd == "" {
		c.sshd = sshdEntry{}
		return sshdEntry{service: defaultSSHDPAMService}
	}

	fingerprint, configFiles := c.sshdFingerprint(sshd)
	now := c.now()
	maxAge := sshdUsePAMMaxAge
	if c.sshd.usePAM == "" {
		maxAge = sshdUsePAMRetryAfter
	}
	if c.sshd.checked && c.sshd.fingerprint == fingerprint && now.Sub(c.sshd.at) < maxAge {
		return c.sshd
	}

	entry := sshdEntry{checked: true, fingerprint: fingerprint, at: now, service: defaultSSHDPAMService}
	ctx, cancel := context.WithTimeout(context.Background(), pamQueryTimeout)
	out, err := c.runSSHDT(ctx, sshd)
	cancel()
	if err == nil {
		entry.usePAM = parseSSHDUsePAM(string(out))
		if service := parseSSHDPAMServiceName(string(out)); service != "" {
			entry.service = service
		}
	}
	for _, f := range configFiles {
		data, _, _, ok := c.readSmallFile(f, fileStamp{})
		if ok && sshdConfigSetsServiceInMatch(string(data)) {
			entry.matchScoped = true
			break
		}
	}
	c.sshd = entry
	return entry
}

// parseSSHDPAMServiceName returns the pamservicename line of sshd -T output
// (OpenSSH 9.8 and later), normalized as libpam's pam_start does: only the
// part after the last '/', lowercased. Older sshd prints no such line.
func parseSSHDPAMServiceName(out string) string {
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.EqualFold(fields[0], "pamservicename") {
			name := fields[1]
			if i := strings.LastIndexByte(name, '/'); i >= 0 {
				name = name[i+1:]
			}
			return strings.ToLower(name)
		}
	}
	return ""
}

// sshdConfigSetsServiceInMatch reports whether an sshd config file sets
// PAMServiceName after a Match line other than "Match all", where it applies
// only to the connections that match.
func sshdConfigSetsServiceInMatch(config string) bool {
	inMatch := false
	for line := range strings.SplitSeq(config, "\n") {
		args := sshdConfigArgs(line)
		if len(args) == 0 {
			continue
		}
		switch strings.ToLower(args[0]) {
		case "match":
			inMatch = len(args) != 2 || !strings.EqualFold(args[1], "all")
		case "pamservicename":
			if inMatch {
				return true
			}
		}
	}
	return false
}

// sshdConfigArgs splits an sshd config line into its keyword and arguments:
// blanks separate them, the keyword may also end in '=', and a token starting
// with '#' begins a comment.
func sshdConfigArgs(line string) []string {
	fields := strings.Fields(line)
	if len(fields) > 0 {
		if keyword, rest, found := strings.Cut(fields[0], "="); found {
			fields = slices.Insert(fields[1:], 0, keyword)
			if rest != "" {
				fields = slices.Insert(fields, 1, rest)
			}
		}
	}
	for i, f := range fields {
		if strings.HasPrefix(f, "#") {
			return fields[:i]
		}
	}
	return fields
}

// sshdFingerprint identifies the inputs of sshd -T by their stamps: the
// binary, the main config files, every drop-in in their .d directories and
// the privilege separation directory. It also returns the config files that
// exist, for the Match scan.
func (c *loginCaptureCollector) sshdFingerprint(sshd string) (string, []string) {
	var b strings.Builder
	var files []string
	stampInto(&b, sshd)
	stampInto(&b, filepath.Join(c.root, sshdPrivsepDir))
	for _, f := range sshdConfigFiles {
		p := filepath.Join(c.root, f)
		if stampInto(&b, p) {
			files = append(files, p)
		}
	}
	for _, d := range sshdConfigDirs {
		dir := filepath.Join(c.root, d)
		stampInto(&b, dir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			if stampInto(&b, p) {
				files = append(files, p)
			}
		}
	}
	return b.String(), files
}

// stampInto appends p and its stamp to b and reports whether p exists.
func stampInto(b *strings.Builder, p string) bool {
	b.WriteString(p)
	info, err := os.Stat(p)
	if err == nil {
		b.WriteString("|" + stampOf(info).String())
	}
	b.WriteByte('\n')
	return err == nil
}
