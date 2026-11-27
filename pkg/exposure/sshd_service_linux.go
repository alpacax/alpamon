//go:build linux

package exposure

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"maps"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Debian package versions include an optional epoch and a distribution revision.
var opensshVersion = regexp.MustCompile(`^(?:[0-9]+:)?([0-9]+)\.([0-9]+)p[0-9]+(?:-[A-Za-z0-9.+~]+)?$`)

const maxPackageStatusBytes = 64 << 20

func modernSSHD(ctx context.Context, sys systemFiles) bool {
	file, before, _, _ := sys.f.openRegular("/var/lib/dpkg/status", ownerRule{system: true})
	if file == nil {
		return false
	}
	defer func() { _ = file.Close() }()
	if !installedModernSSHD(ctx, file, before.Size) {
		return false
	}
	var after unix.Stat_t
	return unix.Fstat(int(file.Fd()), &after) == nil && !changed(&before, &after) && before.Ctim == after.Ctim
}

func installedModernSSHD(ctx context.Context, r io.Reader, size int64) bool {
	lines := bufio.NewReader(io.LimitReader(r, maxPackageStatusBytes))
	var pkg, status, version string
	var continuation bool
	for ctx.Err() == nil {
		line, more, err := lines.ReadLine()
		if err == io.EOF {
			// A final stanza may end at EOF, but not at the scan cutoff.
			return size <= maxPackageStatusBytes && pkg == "openssh-server" && supportedSSHDPackage(status, version)
		}
		if err != nil {
			return false
		}
		rest := continuation
		continuation = more
		if rest {
			continue
		}
		if len(line) == 0 {
			if pkg == "openssh-server" {
				return supportedSSHDPackage(status, version)
			}
			pkg, status, version = "", "", ""
			continue
		}
		key, value, _ := bytes.Cut(line, []byte(": "))
		if more {
			// None of the three supported field values needs a second buffer.
			value = nil
		}
		switch string(key) {
		case "Package":
			pkg = string(value)
		case "Status":
			status = string(value)
		case "Version":
			version = string(value)
		}
	}
	return false
}

func supportedSSHDPackage(status, version string) bool {
	match := opensshVersion.FindStringSubmatch(version)
	if status != "install ok installed" || match == nil {
		return false
	}
	major, err := strconv.Atoi(match[1])
	minor, err2 := strconv.Atoi(match[2])
	return err == nil && err2 == nil && (major > 8 || major == 8 && minor >= 7)
}

// System unit load path, highest priority first. /lib also serves older
// Debian installations where it is separate from /usr/lib.
var sshUnitDirs = []string{
	"/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
	"/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached",
	"/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator",
	"/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
	"/run/systemd/generator.late",
}

// enabledSSHUnit returns the single enabled ssh or sshd unit of the requested
// type. An unreadable dependency directory or two enabled names is ambiguous.
func enabledSSHUnit(ctx context.Context, src sshUnitSource, suffix string, targets ...string) (name, file string, ok bool) {
	for _, candidate := range []string{"ssh" + suffix, "sshd" + suffix} {
		for _, target := range targets {
			for _, dependency := range []string{".wants", ".requires"} {
				for _, dir := range sshUnitDirs {
					if ctx.Err() != nil {
						return "", "", false
					}
					entry, status := src.unitEntry(path.Join(dir, target+dependency, candidate))
					if status == statusAbsent {
						continue
					}
					if status != statusRead || !entry.stableAt(src.boot) || entry.target == "" || name != "" && name != candidate {
						return "", "", false
					}
					if name == "" {
						name = candidate
						selected, ok := sshUnitFile(ctx, src, candidate)
						if !ok || !selected.canRead(src.boot) {
							return "", "", false
						}
						file = selected.file
					}
					actual, ok := src.resolveUnitTarget(entry.target)
					if !ok || actual != file {
						return "", "", false
					}
					// Lower-priority entries with the same dependency basename are shadowed.
					break
				}
			}
		}
	}
	return name, file, true
}

// systemd may still have the pre-edit unit loaded. Check the timestamp of
// each selected file on the same descriptor used to read its contents.
type sshUnitSource struct {
	systemFiles
	boot time.Time
}

func (s sshUnitSource) load(name string) loaded {
	l := s.systemFiles.load(name)
	if l.usable() && (l.mtime.After(s.boot) || bytes.IndexByte(l.data, '\r') >= 0) {
		clear(l.data)
		return failed(statusRejected, reasonFileRejected)
	}
	return l
}

func safeSSHDService(ctx context.Context, sys systemFiles, binary, procRoot string) bool {
	btime, ok := procBootTime(procRoot)
	if !ok || btime <= 0 {
		return false
	}
	src := sshUnitSource{sys, time.Unix(btime, 0)}
	direct, directFile, ok := enabledSSHUnit(ctx, src, ".service", "multi-user.target")
	if !ok {
		return false
	}
	targets := []string{"sockets.target", "multi-user.target"}
	if direct != "" {
		targets = append(targets, direct)
	}
	socket, socketFile, ok := enabledSSHUnit(ctx, src, ".socket", targets...)
	if !ok {
		return false
	}
	file := directFile
	if socket == "" {
		// Some packages enable the service directly in multi-user.target.
		if file == "" {
			return false
		}
	} else {
		var selection sshSocket
		if !readSSHUnit(ctx, src, socketFile, "[Socket]", selection.set) {
			return false
		}
		name := selection.service
		if name == "" {
			base := strings.TrimSuffix(path.Base(socketFile), ".socket")
			if selection.accept {
				base += "@"
			}
			name = base + ".service"
		} else if selection.accept || !plainServiceName.MatchString(name) {
			return false
		}
		selected, ok := sshUnitFile(ctx, src, name)
		if !ok || !selected.canRead(src.boot) {
			return false
		}
		file = selected.file
	}
	service := sshService{binary: binary}
	return readSSHUnit(ctx, src, file, "[Service]", service.set) && service.safeStart(ctx, src)
}

var plainServiceName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*\.service$`)

type sshSocket struct {
	accept  bool
	service string
}

func (s *sshSocket) set(key, value string) bool {
	switch key {
	case "ExecStartPre", "ExecStartPost":
		return value == ""
	case "Service":
		s.service = value
	case "Accept":
		switch value {
		case "1", "yes", "true", "on":
			s.accept = true
		case "0", "no", "false", "off":
			s.accept = false
		default:
			return false
		}
	}
	return true
}

type sshUnitEntry struct {
	mtime   time.Time
	runtime bool
	file    string
	target  string
}

func (entry sshUnitEntry) stableAt(boot time.Time) bool {
	return !entry.runtime && !entry.mtime.After(boot)
}

func (entry sshUnitEntry) canRead(boot time.Time) bool {
	return entry.target == "" && entry.stableAt(boot)
}

// Pin the leaf before inspecting its owner, time and link text. The rooted
// walk supplies the real parent for relative links, including on merged /usr.
func (src sshUnitSource) unitEntry(file string) (sshUnitEntry, string) {
	var entry sshUnitEntry
	parent, name, dirs, l, ok := src.f.walkDirs(file, ownerRule{system: true}, false)
	if !ok {
		return entry, l.status
	}
	if parent != src.f.rootFD {
		defer func() { _ = unix.Close(parent) }()
	}
	fd, err := src.f.openAt(parent, name, unix.O_PATH)
	if err != nil {
		status, _ := statusOf(err)
		return entry, status
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || src.f.mapOwner(file, st.Uid) != 0 {
		return entry, statusRejected
	}
	dir := dirs[len(dirs)-1].path
	entry.file = path.Join(dir, name)
	entry.runtime = l.viaRun
	entry.mtime = mtimeOf(&st)
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return entry, statusRead
	case unix.S_IFLNK:
		var buf [unix.PathMax]byte
		n, err := unix.Readlinkat(fd, "", buf[:])
		if err != nil || n == 0 || n == len(buf) {
			return entry, statusRejected
		}
		target := string(buf[:n])
		if !path.IsAbs(target) {
			// Resolve leading parent components from the pinned directory.
			// Interior dot components would require another symlink walk.
			for strings.HasPrefix(target, "../") {
				target, dir = target[3:], path.Dir(dir)
			}
			target = strings.TrimPrefix(target, "./")
			if !validPath("/" + target) {
				return entry, statusRejected
			}
			target = path.Join(dir, target)
		}
		// A mask can rule out an unrelated alias during discovery. A
		// masked unit cannot supply the selected socket or service.
		if target == "/dev/null" {
			entry.target = target
			return entry, statusRead
		}
		if !validPath(target) || !slices.Contains(sshUnitDirs, path.Dir(target)) || path.Ext(target) != path.Ext(name) ||
			strings.Contains(path.Base(target), "@") != strings.Contains(name, "@") {
			return entry, statusRejected
		}
		entry.target = target
		return entry, statusRead
	default:
		return entry, statusRejected
	}
}

// Follow the exact path in the dependency link, without substituting a
// higher-priority unit of the same name for a missing or shadowed target.
func (src sshUnitSource) resolveUnitTarget(target string) (string, bool) {
	for range maxIncludeDepth {
		entry, status := src.unitEntry(target)
		if status != statusRead || !entry.stableAt(src.boot) || entry.target == "/dev/null" {
			break
		}
		if entry.target == "" {
			return entry.file, true
		}
		target = entry.target
	}
	return "", false
}

func sshUnitFile(ctx context.Context, src sshUnitSource, name string) (sshUnitEntry, bool) {
	var expected string
	var runtimeAlias bool
	var newest time.Time
	for range maxIncludeDepth {
		if ctx.Err() != nil {
			break
		}
		var entry sshUnitEntry
		for _, dir := range sshUnitDirs {
			var status string
			entry, status = src.unitEntry(path.Join(dir, name))
			if status == statusAbsent {
				continue
			}
			if status != statusRead {
				return sshUnitEntry{}, false
			}
			break
		}
		if entry.file == "" || expected != "" && entry.file != expected {
			return sshUnitEntry{}, false
		}
		if entry.mtime.After(newest) {
			newest = entry.mtime
		}
		if entry.target == "" || entry.target == "/dev/null" {
			entry.mtime = newest
			entry.runtime = entry.runtime || runtimeAlias
			return entry, true
		}
		target, status := src.unitEntry(entry.target)
		if status != statusRead {
			return sshUnitEntry{}, false
		}
		if target.mtime.After(newest) {
			newest = target.mtime
		}
		runtimeAlias = runtimeAlias || entry.runtime || target.runtime
		expected, name = target.file, path.Base(entry.target)
	}
	return sshUnitEntry{}, false
}

func unitNameGroups(name string) []string {
	groups := []string{name}
	suffix := path.Ext(name)
	for prefix := strings.TrimSuffix(name, suffix); strings.Contains(prefix, "-"); {
		i := strings.LastIndexByte(prefix, '-')
		prefix = prefix[:i]
		groups = append(groups, prefix+"-"+suffix)
	}
	return groups
}

// Only examine other unit names when their drop-ins could also apply to the
// selected unit through an alias. An instance-specific command is unknown
// until the individual connection is known.
func sshUnitNames(ctx context.Context, src sshUnitSource, canonical string) ([]string, bool) {
	suffix := path.Ext(canonical)
	template := strings.HasSuffix(canonical, "@"+suffix)
	instances := map[string]bool{}
	units, dropIns := map[string]bool{}, map[string]bool{}
	for _, dir := range sshUnitDirs {
		if ctx.Err() != nil {
			return nil, false
		}
		entries, l := src.list(dir)
		if !l.complete() {
			return nil, false
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry, ".") {
				continue
			}
			name, drop := strings.CutSuffix(entry, ".d")
			if !strings.HasSuffix(name, suffix) {
				continue
			}
			if template {
				if prefix, instance, ok := strings.Cut(name, "@"); ok && instance != suffix {
					instances[prefix+"@"+suffix] = true
				}
			}
			if drop {
				dropIns[name] = true
			} else {
				units[name] = true
			}
		}
	}
	names := []string{canonical}
	inspected := 0
	for name := range units {
		if ctx.Err() != nil {
			return nil, false
		}
		if instances[name] {
			if name == canonical {
				return nil, false
			}
			unit, ok := sshUnitFile(ctx, src, name)
			if !ok || path.Base(unit.file) == canonical {
				return nil, false
			}
		}
		if name == canonical {
			continue
		}
		for _, group := range unitNameGroups(name) {
			if !dropIns[group] {
				continue
			}
			inspected++
			if inspected > maxIncludeFiles {
				return nil, false
			}
			unit, ok := sshUnitFile(ctx, src, name)
			if !ok {
				return nil, false
			}
			if path.Base(unit.file) == canonical {
				// Priority between competing aliases with the same drop-in
				// filename is outside the supported service grammar.
				if !unit.stableAt(src.boot) || len(names) > 1 {
					return nil, false
				}
				names = append(names, name)
			}
			break
		}
	}
	return names, true
}

// Load the highest-priority main unit and one drop-in per basename. systemd
// applies the surviving filenames in lexical order across all directories.
func readSSHUnit(ctx context.Context, src sshUnitSource, file, section string, set func(string, string) bool) bool {
	name := path.Base(file)
	names, ok := sshUnitNames(ctx, src, name)
	if !ok {
		return false
	}
	read := func(l loaded) bool {
		active := ""
		return serviceLines(l, func(line string) bool {
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				active = line
				return true
			}
			key, value, ok := strings.Cut(line, "=")
			return ok && active != "" && (active != section || set(strings.TrimSpace(key), strings.TrimSpace(value)))
		})
	}
	if !read(src.load(file)) {
		return false
	}
	dropIns := map[string]string{}
	add := func(dir, group string) bool {
		if ctx.Err() != nil {
			return false
		}
		d := path.Join(dir, group+".d")
		files, l := src.f.listBefore(d, ownerRule{system: true}, false, src.boot)
		if !l.complete() {
			return false
		}
		for _, file := range files {
			// systemd skips hidden files. Its backup suffixes already exclude .conf.
			if !strings.HasPrefix(file, ".") && strings.HasSuffix(file, ".conf") && dropIns[file] == "" {
				if len(dropIns) >= maxIncludeFiles {
					return false
				}
				dropIns[file] = path.Join(d, file)
			}
		}
		return true
	}
	for _, candidate := range names {
		groups := unitNameGroups(candidate)
		for _, dir := range sshUnitDirs {
			for _, group := range groups {
				if !add(dir, group) {
					return false
				}
			}
		}
	}
	for _, dir := range sshUnitDirs {
		if !add(dir, strings.TrimPrefix(path.Ext(name), ".")) {
			return false
		}
	}
	for _, file := range slices.Sorted(maps.Keys(dropIns)) {
		if ctx.Err() != nil {
			return false
		}
		entry, status := src.unitEntry(dropIns[file])
		if status != statusRead || !entry.canRead(src.boot) || !read(src.load(entry.file)) {
			return false
		}
	}
	return ctx.Err() == nil
}

type sshService struct {
	binary    string
	unsafePre bool
	start     string
	starts    int
	envFiles  []string
}

// Only simple, single-line ASCII directives are modeled. Unit and environment
// contents are discarded as soon as the current file has been checked.
func serviceLines(l loaded, visit func(string) bool) bool {
	defer clear(l.data)
	ok := l.usable()
	if ok {
		forEachLine(l.data, func(raw []byte, long bool) bool {
			line := strings.Trim(string(raw), " \t")
			if long || strings.HasSuffix(line, `\`) {
				ok = false
			} else if line != "" && line[0] != '#' && line[0] != ';' {
				ok = strings.IndexFunc(line, func(r rune) bool { return (r < ' ' && r != '\t') || r > '~' }) < 0 && visit(line)
			}
			return ok
		})
	}
	return ok
}

func (s *sshService) set(key, value string) bool {
	switch key {
	case "ExecStart":
		if value == "" {
			s.starts = 0
		} else {
			s.starts++
		}
		s.start = value
	case "EnvironmentFile":
		if value == "" {
			s.envFiles = nil
			break
		}
		file := strings.TrimPrefix(value, "-")
		if !validPath(file) || strings.ContainsAny(file, "%$*?[]") || len(s.envFiles) >= maxIncludeFiles {
			return false
		}
		s.envFiles = append(s.envFiles, value)
	case "ExecStartPre":
		if value == "" {
			s.unsafePre = false
		} else {
			args := strings.Fields(value)
			s.unsafePre = s.unsafePre || len(args) != 2 || strings.TrimPrefix(args[0], "-") != s.binary || args[1] != "-t"
		}
	case "ExecReload", "StandardInput", "RuntimeDirectory", "RuntimeDirectoryMode", "RuntimeDirectoryPreserve", "Type", "KillMode", "Restart", "RestartPreventExitStatus":
	default:
		return false
	}
	return true
}

func serviceFlags(value string) bool {
	for _, flag := range strings.Fields(value) {
		switch flag {
		case "-i", "-D", "-e", "-4", "-6":
		default:
			return false
		}
	}
	return true
}

func (s *sshService) safeStart(ctx context.Context, src systemSource) bool {
	args := strings.Fields(s.start)
	if s.unsafePre || s.starts != 1 || len(args) == 0 || s.binary == "" || strings.TrimPrefix(args[0], "-") != s.binary {
		return false
	}
	expandsOpts, requiresEmpty := false, false
	for _, arg := range args[1:] {
		if arg == "$SSHD_OPTS" || arg == "${SSHD_OPTS}" {
			expandsOpts = true
			requiresEmpty = requiresEmpty || arg == "${SSHD_OPTS}"
		} else if !serviceFlags(arg) {
			return false
		}
	}
	assigned := false
	for _, file := range s.envFiles {
		if ctx.Err() != nil {
			return false
		}
		name, optional := strings.CutPrefix(file, "-")
		l := src.load(name)
		if optional && l.status == statusAbsent {
			continue
		}
		set, ok := readSSHDEnvironment(l, requiresEmpty)
		if !ok {
			return false
		}
		assigned = assigned || set
	}
	return ctx.Err() == nil && (!expandsOpts || assigned)
}

func readSSHDEnvironment(l loaded, requiresEmpty bool) (assigned, ok bool) {
	ok = serviceLines(l, func(line string) bool {
		name, value, ok := strings.Cut(line, "=")
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if !ok || name != "SSHD_OPTS" || (requiresEmpty && value != "") || !serviceFlags(value) {
			return false
		}
		assigned = true
		return true
	})
	return assigned, ok
}
