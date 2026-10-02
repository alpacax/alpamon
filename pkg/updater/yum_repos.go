package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
)

var (
	// YumReposDirs is the union of the directories dnf 4 and dnf 5 read repo files from by default;
	// a reposdir in the main config replaces it.
	// It is a var so tests can point it at a temp dir.
	YumReposDirs = []string{"/etc/yum.repos.d", "/etc/yum/repos.d", "/etc/distro.repos.d", "/usr/share/dnf5/repos.d"}

	// YumBinary, DnfConfFile and YumConfFile locate the yum command and the main configs it may read;
	// a reposdir set in that config's [main] replaces YumReposDirs. They are vars so tests can move them.
	YumBinary   = "/usr/bin/yum"
	DnfConfFile = "/etc/dnf/dnf.conf"
	YumConfFile = "/etc/yum.conf"

	// yumUnreachableRepoRe matches yum 3 stopping at a repo whose mirrorlist fails, which skip_if_unavailable
	// does not cover; yum prints the id followed by /$releasever/$basearch.
	yumUnreachableRepoRe = regexp.MustCompile(`Cannot find a valid baseurl for repo: ([^/\s]+)`)

	yumFalseValues = map[string]bool{"0": true, "no": true, "false": true, "off": true}

	// yumLocationKeys name where packages come from; name or gpgkey may mention the alpamon URL on any repo.
	yumLocationKeys = map[string]bool{"baseurl": true, "mirrorlist": true, "metalink": true}
)

type yumRepo struct {
	id               string
	enabled, alpamon bool
}

// YumArgv returns the yum argv for verb -y args that lets every enabled repo but alpamon's be skipped
// when it fails to load: yum and dnf load all enabled repos first, and one that fails fails the command.
// It passes --disablerepo for each repo in disabled, the list RunYum returns.
func YumArgv(disabled []string, verb string, args ...string) []string {
	return yumArgv(withDisabledRepos(yumSkipUnavailableSetopts(scanYumRepos()), disabled), verb, args)
}

// RunYum runs YumArgv(disabled, verb, args...) through run. When yum 3 stops at a repo whose mirrorlist fails,
// it disables that repo and runs the command again, unless the repo is alpamon's or alpamon's repo did not
// resolve. It returns disabled with every repo it added.
func RunYum(run func(argv ...string) (int, string, error), disabled []string, verb string, args ...string) (int, string, []string, error) {
	disabled = slices.Clip(disabled)
	repos := scanYumRepos()
	setopts := yumSkipUnavailableSetopts(repos)
	if setopts == nil {
		code, out, err := run(yumArgv(withDisabledRepos(nil, disabled), verb, args)...)
		return code, out, disabled, err
	}
	for {
		code, out, err := run(yumArgv(withDisabledRepos(setopts, disabled), verb, args)...)
		id := unreachableYumRepo(out)
		if code == 0 || !skippableYumRepo(repos, id) || slices.Contains(disabled, id) {
			if len(disabled) > 0 {
				out = strings.TrimRight(out, "\n") + fmt.Sprintf("\n\nDisabled yum repos whose mirrorlist could not be reached: %s.", strings.Join(disabled, ", "))
			}
			return code, out, disabled, err
		}
		log.Warn().Str("repo", id).Msg("A yum repo's mirrorlist could not be reached; running yum again with it disabled.")
		disabled = append(disabled, id)
	}
}

func withDisabledRepos(opts, disabled []string) []string {
	opts = slices.Clip(opts)
	for _, id := range disabled {
		opts = append(opts, "--disablerepo="+id)
	}
	return opts
}

func yumArgv(opts []string, verb string, args []string) []string {
	argv := append([]string{"yum"}, opts...)
	return append(append(argv, verb, "-y"), args...)
}

func unreachableYumRepo(out string) string {
	if m := yumUnreachableRepoRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

func skippableYumRepo(repos []yumRepo, id string) bool {
	return slices.ContainsFunc(repos, func(r yumRepo) bool { return r.id == id && r.enabled && !r.alpamon })
}

// yumSkipUnavailableSetopts returns YumArgv's flags, or nil when alpamon's repo does not resolve:
// skipping alpamon's own repo would turn its outage into "Nothing to do." and a successful exit.
func yumSkipUnavailableSetopts(repos []yumRepo) []string {
	// A glob, not one option per repo: dnf5 exits 2 on a setopt naming an id it does not load,
	// such as a file outside its reposdir or a section name holding $releasever.
	var strict []string
	for _, r := range repos {
		if r.enabled && r.alpamon {
			strict = append(strict, "--setopt="+r.id+".skip_if_unavailable=False")
		}
	}
	if len(strict) == 0 {
		log.Debug().Msg("Could not resolve the alpamon yum repo; running yum without repo options.")
		return nil
	}
	setopts := append([]string{"--setopt=*.skip_if_unavailable=True"}, strict...)
	log.Debug().Strs("setopts", setopts).Msg("Skipping unavailable yum repos other than alpamon's.")
	return setopts
}

func scanYumRepos() []yumRepo {
	var repos []yumRepo
	for _, dir := range yumReposDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".repo") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			repos = append(repos, parseYumRepos(string(data))...)
		}
	}
	return repos
}

func yumReposDirs() []string {
	if data, err := os.ReadFile(yumMainConf()); err == nil {
		if dirs := parseYumReposdir(string(data)); len(dirs) > 0 {
			return dirs
		}
	}
	return YumReposDirs
}

// yumMainConf returns the main config the yum command reads: dnf.conf when yum is a link to dnf, else
// yum.conf, which yum 3 keeps reading on CentOS 7 even with dnf installed beside it.
func yumMainConf() string {
	if target, err := filepath.EvalSymlinks(YumBinary); err == nil && !strings.HasPrefix(filepath.Base(target), "dnf") {
		return YumConfFile
	}
	return DnfConfFile
}

// parseYumReposdir returns the last reposdir in [main], split on commas and whitespace as yum's list options are.
func parseYumReposdir(data string) []string {
	var dirs []string
	inMain, inReposdir := false, false
	split := func(value string) []string {
		return strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	}
	for line := range strings.SplitSeq(data, "\n") {
		// An indented line continues the previous key's list, as baseurl's does.
		continued := line != strings.TrimLeft(line, " \t")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if continued && inReposdir {
			dirs = append(dirs, split(line)...)
			continue
		}
		inReposdir = false
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inMain = strings.TrimSpace(line[1:len(line)-1]) == "main"
			continue
		}
		k, value, ok := strings.Cut(line, "=")
		if inMain && ok && strings.ToLower(strings.TrimSpace(k)) == "reposdir" {
			dirs, inReposdir = split(value), true
		}
	}
	return dirs
}

func parseYumRepos(data string) []yumRepo {
	var repos []yumRepo
	var key string
	for line := range strings.SplitSeq(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			repos = append(repos, yumRepo{id: strings.TrimSpace(line[1 : len(line)-1]), enabled: true})
			key = ""
		case len(repos) == 0:
		default:
			r := &repos[len(repos)-1]
			// A line that is not "key=value" continues the previous key's list, as baseurl allows.
			k, value, ok := strings.Cut(line, "=")
			if ok && !strings.ContainsAny(k, ":/") {
				key, value = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(value)
				if key == "enabled" {
					r.enabled = !yumFalseValues[strings.ToLower(value)]
				}
			} else {
				value = line
			}
			if yumLocationKeys[key] && ContainsAlpamonRepo(value) {
				r.alpamon = true
			}
		}
	}
	return repos
}
