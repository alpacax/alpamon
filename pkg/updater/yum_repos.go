package updater

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

var (
	// YumReposDirs is the union of the directories dnf 4 and dnf 5 read repo files from by default.
	// It is a var so tests can point it at a temp dir.
	YumReposDirs = []string{"/etc/yum.repos.d", "/etc/yum/repos.d", "/etc/distro.repos.d", "/usr/share/dnf5/repos.d"}

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
func YumArgv(verb string, args ...string) []string {
	argv := append([]string{"yum"}, yumSkipUnavailableSetopts()...)
	return append(append(argv, verb, "-y"), args...)
}

// yumSkipUnavailableSetopts returns YumArgv's flags, or nil when alpamon's repo does not resolve:
// skipping alpamon's own repo would turn its outage into "Nothing to do." and a successful exit.
func yumSkipUnavailableSetopts() []string {
	var repos []yumRepo
	for _, dir := range YumReposDirs {
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

	// A glob, not one option per repo: dnf5 exits 2 on a setopt naming an id it does not load,
	// such as a file outside its reposdir or a section name holding $releasever.
	setopts := []string{"--setopt=*.skip_if_unavailable=True"}
	for _, r := range repos {
		if r.enabled && r.alpamon {
			setopts = append(setopts, "--setopt="+r.id+".skip_if_unavailable=False")
		}
	}
	if len(setopts) == 1 {
		log.Debug().Msg("Could not resolve the alpamon yum repo; running yum without repo options.")
		return nil
	}
	log.Debug().Strs("setopts", setopts).Msg("Skipping unavailable yum repos other than alpamon's.")
	return setopts
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
