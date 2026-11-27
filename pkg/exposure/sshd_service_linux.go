//go:build linux

package exposure

import (
	"bytes"
	"context"
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

func modernSSHD(src systemSource) bool {
	l := src.load("/var/lib/dpkg/status")
	defer clear(l.data)
	if !l.usable() {
		return false
	}
	found := false
	for stanza := range bytes.SplitSeq(l.data, []byte("\n\n")) {
		var pkg, status, version string
		for line := range bytes.SplitSeq(stanza, []byte("\n")) {
			switch key, value, _ := strings.Cut(string(line), ": "); key {
			case "Package":
				pkg = value
			case "Status":
				status = value
			case "Version":
				version = value
			}
		}
		if pkg != "openssh-server" {
			continue
		}
		match := opensshVersion.FindStringSubmatch(version)
		if found || status != "install ok installed" || match == nil {
			return false
		}
		major, err := strconv.Atoi(match[1])
		minor, err2 := strconv.Atoi(match[2])
		if err != nil || err2 != nil || major < 8 || major == 8 && minor < 7 {
			return false
		}
		found = true
	}
	return found
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
func enabledSSHUnit(fs *fsReader, suffix string, targets ...string) (string, bool) {
	var selected string
	for _, name := range []string{"ssh" + suffix, "sshd" + suffix} {
		for _, target := range targets {
			for _, dir := range sshUnitDirs {
				for _, dependency := range []string{".wants", ".requires"} {
					_, l := fs.exists(path.Join(dir, target+dependency, name))
					if l.status == statusAbsent {
						continue
					}
					if l.status != statusRead || l.uid != 0 || l.mode&unix.S_IFMT != unix.S_IFLNK || selected != "" && selected != name {
						return "", false
					}
					selected = name
				}
			}
		}
	}
	return selected, true
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
	direct, directOK := enabledSSHUnit(src.f, ".service", "multi-user.target")
	targets := []string{"sockets.target", "multi-user.target"}
	if directOK && direct != "" {
		targets = append(targets, direct)
	}
	socket, ok := enabledSSHUnit(src.f, ".socket", targets...)
	if !ok {
		return false
	}
	var name string
	if socket == "" {
		// Some packages enable the service directly in multi-user.target.
		if !directOK || direct == "" {
			return false
		}
		name = direct
	} else {
		var selection sshSocket
		socketFile, ok := sshUnitFile(ctx, src, socket)
		if !ok || !readSSHUnit(ctx, src, socketFile, "[Socket]", selection.set) {
			return false
		}
		name = selection.service
		if name == "" {
			base := strings.TrimSuffix(path.Base(socketFile), ".socket")
			if selection.accept {
				base += "@"
			}
			name = base + ".service"
		} else if selection.accept || !plainServiceName.MatchString(name) {
			return false
		}
	}
	service := sshService{binary: binary}
	file, ok := sshUnitFile(ctx, src, name)
	return ok && readSSHUnit(ctx, src, file, "[Service]", service.set) && service.safeStart(ctx, src)
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

// A unit alias names another unit in the search path. Resolve only simple,
// root-owned links inside those directories; masks and external links are unknown.
func sshUnitFile(ctx context.Context, src sshUnitSource, name string) (string, bool) {
	for range maxIncludeDepth {
		if ctx.Err() != nil {
			return "", false
		}
		target := ""
		for _, dir := range sshUnitDirs {
			file := path.Join(dir, name)
			_, l := src.f.exists(file)
			if l.status == statusAbsent {
				continue
			}
			if l.status != statusRead || l.uid != 0 {
				return "", false
			}
			switch l.mode & unix.S_IFMT {
			case unix.S_IFREG:
				return file, true
			case unix.S_IFLNK:
				if l.mtime.After(src.boot) {
					return "", false
				}
				fd, last, _, _, ok := src.f.walkDirs(file, ownerRule{system: true}, false)
				if !ok {
					return "", false
				}
				var buf [unix.PathMax]byte
				n, err := unix.Readlinkat(fd, last, buf[:])
				if fd != src.f.rootFD {
					_ = unix.Close(fd)
				}
				if err != nil || n == len(buf) {
					return "", false
				}
				link := string(buf[:n])
				if !path.IsAbs(link) {
					link = path.Join(dir, link)
				}
				if !slices.Contains(sshUnitDirs, path.Dir(link)) || path.Ext(link) != path.Ext(name) || strings.Contains(path.Base(link), "@") != strings.Contains(name, "@") {
					return "", false
				}
				target = path.Base(link)
			default:
				return "", false
			}
			break
		}
		if target == "" {
			return "", false
		}
		name = target
	}
	return "", false
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
			file, ok := sshUnitFile(ctx, src, name)
			if !ok || path.Base(file) == canonical {
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
			file, ok := sshUnitFile(ctx, src, name)
			if !ok {
				return nil, false
			}
			if path.Base(file) == canonical {
				// Priority between competing aliases with the same drop-in
				// filename is outside the supported service grammar.
				if len(names) > 1 {
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
		files, l := src.list(d)
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
		if ctx.Err() != nil || !read(src.load(dropIns[file])) {
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
	expandsOpts := false
	for _, arg := range args[1:] {
		if arg == "$SSHD_OPTS" || arg == "${SSHD_OPTS}" {
			expandsOpts = true
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
		set, ok := readSSHDEnvironment(l)
		if !ok {
			return false
		}
		assigned = assigned || set
	}
	return ctx.Err() == nil && (!expandsOpts || assigned)
}

func readSSHDEnvironment(l loaded) (assigned, ok bool) {
	ok = serviceLines(l, func(line string) bool {
		name, value, ok := strings.Cut(line, "=")
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if !ok || name != "SSHD_OPTS" || !serviceFlags(value) {
			return false
		}
		assigned = true
		return true
	})
	return assigned, ok
}
