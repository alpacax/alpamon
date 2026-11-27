//go:build linux

package exposure

import (
	"bytes"
	"context"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
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

var sshUnitDirs = []string{"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}

type sshService struct {
	start    string
	envFiles []string
}

// Accept only literal starts and simple environment assignments. An unmodeled
// override makes the derived policy unknown even if systemd could resolve it.
func safeSSHDServices(ctx context.Context, src systemFiles) bool {
	remaining := maxIncludeFiles
	verified := false
	for _, name := range []string{"ssh@.service", "sshd@.service"} {
		var service sshService
		found := false
		for _, dir := range sshUnitDirs {
			base := path.Join(dir, name)
			if !found {
				l := src.load(base)
				if l.status != statusAbsent {
					if !service.read(l) {
						return false
					}
					found = true
				}
			}
			// Check every candidate drop-in. Do not try to reconcile overrides.
			names, l := src.list(base + ".d")
			if !l.complete() {
				return false
			}
			for _, entry := range names {
				if strings.HasSuffix(entry, ".conf") {
					remaining--
					if remaining < 0 || ctx.Err() != nil || !service.read(src.load(base+".d/"+entry)) {
						return false
					}
				}
			}
		}
		if found {
			if !service.safeStart(ctx, src) {
				return false
			}
			verified = true
		} else if service.start != "" || len(service.envFiles) != 0 {
			return false
		}
	}
	if !verified {
		return false
	}
	// A socket can start a regular service even when a per-connection
	// template is installed. Only the templates are inspected; a competing
	// unit makes selection uncertain, including an unreadable or masked unit.
	for _, dir := range sshUnitDirs {
		for _, name := range []string{"ssh.service", "sshd.service"} {
			if ctx.Err() != nil {
				return false
			}
			if _, l := src.f.exists(path.Join(dir, name)); l.status != statusAbsent {
				return false
			}
		}
	}
	return ctx.Err() == nil
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

func (s *sshService) read(l loaded) bool {
	section := ""
	return serviceLines(l, func(line string) bool {
		switch line {
		case "[Unit]", "[Service]", "[Install]":
			section = line
			return true
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			return false
		}
		if section != "[Service]" {
			return true
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "ExecStart":
			if s.start != "" || value == "" {
				return false
			}
			s.start = value
		case "EnvironmentFile":
			file := strings.TrimPrefix(value, "-")
			if !validPath(file) || strings.ContainsAny(file, "%$*?[]") || len(s.envFiles) >= maxIncludeFiles {
				return false
			}
			s.envFiles = append(s.envFiles, file)
		case "StandardInput", "RuntimeDirectory", "RuntimeDirectoryMode", "RuntimeDirectoryPreserve", "Type", "KillMode", "Restart", "RestartPreventExitStatus":
		default:
			return false
		}
		return true
	})
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
	if len(args) == 0 || !slices.Contains(sshdCandidates, args[0]) {
		return false
	}
	env := map[string]bool{}
	for _, name := range s.envFiles {
		if ctx.Err() != nil || !readSSHDEnvironment(src.load(name), env) {
			return false
		}
	}
	for _, arg := range args[1:] {
		if !serviceFlags(arg) && !(strings.HasPrefix(arg, "$") && env[arg[1:]]) {
			return false
		}
	}
	return true
}

func readSSHDEnvironment(l loaded, env map[string]bool) bool {
	return serviceLines(l, func(line string) bool {
		name, value, ok := strings.Cut(line, "=")
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if !ok || name != "SSHD_OPTS" || !serviceFlags(value) {
			return false
		}
		env[name] = true
		return true
	})
}
