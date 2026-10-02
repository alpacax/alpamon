package updater

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// yumAlpamonRepoFile is the file the PackageCloud one-liner writes on an el9 host.
const yumAlpamonRepoFile = `[alpacax_alpamon]
name=alpacax_alpamon
baseurl=https://packagecloud.io/alpacax/alpamon/el/9/$basearch
repo_gpgcheck=1
gpgcheck=0
enabled=1

[alpacax_alpamon-source]
name=alpacax_alpamon-source
baseurl=https://packagecloud.io/alpacax/alpamon/el/9/SRPMS
enabled=1
`

const yumThirdPartyRepoFile = `# Docker CE
[docker-ce-stable]
name=Docker CE Stable
baseurl=https://download.docker.com/linux/rhel/$releasever/$basearch/stable
enabled=1

[docker-ce-test]
name=Docker CE Test
baseurl=https://download.docker.com/linux/rhel/$releasever/$basearch/test
enabled=0
`

// TestMain points YumReposDirs at an empty temp dir, so no test reads the host's repo files.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "alpamon-yum-repos")
	if err != nil {
		panic(err)
	}
	YumReposDirs = []string{dir}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func setYumReposDirs(t *testing.T, dirs ...string) {
	t.Helper()
	orig := YumReposDirs
	YumReposDirs = dirs
	t.Cleanup(func() { YumReposDirs = orig })
}

func writeYumRepos(t *testing.T, files map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644))
	}
	setYumReposDirs(t, dir)
}

func TestYumSkipUnavailableSetopts_ReadsEnabledLikeYum(t *testing.T) {
	const url = "\nbaseurl=https://packagecloud.io/alpacax/alpamon/el/9/$basearch\n"
	writeYumRepos(t, map[string]string{
		"alpacax_alpamon.repo": "; a comment\n[off-no]" + url + "enabled = No\n\n[off-false]" + url + "enabled=false\n\n" +
			"[on-yes]" + url + "enabled = Yes\n\n[on-true]" + url + "enabled=True\n\n[on-default]" + url,
	})

	assert.Equal(t, []string{
		"--setopt=*.skip_if_unavailable=True",
		"--setopt=on-yes.skip_if_unavailable=False",
		"--setopt=on-true.skip_if_unavailable=False",
		"--setopt=on-default.skip_if_unavailable=False",
	}, yumSkipUnavailableSetopts())
}

// TestYumSkipUnavailableSetopts_NamesNoThirdPartyRepo pins the glob: dnf5 exits 2 on a setopt naming an id it does not load.
func TestYumSkipUnavailableSetopts_NamesNoThirdPartyRepo(t *testing.T) {
	writeYumRepos(t, map[string]string{
		"alpacax_alpamon.repo": yumAlpamonRepoFile,
		"docker-ce.repo":       yumThirdPartyRepoFile,
		"vars.repo":            "[var-$releasever]\nbaseurl=https://example.com/$releasever/\n",
	})

	assert.Equal(t, []string{
		"--setopt=*.skip_if_unavailable=True",
		"--setopt=alpacax_alpamon.skip_if_unavailable=False",
		"--setopt=alpacax_alpamon-source.skip_if_unavailable=False",
	}, yumSkipUnavailableSetopts())
}

// TestYumSkipUnavailableSetopts_MatchesAlpamonOnlyInPackageLocations pins that a third-party repo merely
// naming the alpamon URL outside baseurl, mirrorlist or metalink stays skippable.
func TestYumSkipUnavailableSetopts_MatchesAlpamonOnlyInPackageLocations(t *testing.T) {
	writeYumRepos(t, map[string]string{
		"alpacax_alpamon.repo": yumAlpamonRepoFile,
		"mirror.repo": "[mirror]\nname=mirror of packagecloud.io/alpacax/alpamon/\n" +
			"baseurl=https://mirror.example/el/9/\ngpgkey=https://packagecloud.io/alpacax/alpamon/gpgkey\n",
	})

	assert.Equal(t, []string{
		"--setopt=*.skip_if_unavailable=True",
		"--setopt=alpacax_alpamon.skip_if_unavailable=False",
		"--setopt=alpacax_alpamon-source.skip_if_unavailable=False",
	}, yumSkipUnavailableSetopts())
}

func TestYumSkipUnavailableSetopts_MatchesAlpamonOnAContinuedBaseurlLine(t *testing.T) {
	writeYumRepos(t, map[string]string{
		"alpacax_alpamon.repo": "[alpacax_alpamon]\nbaseurl=https://mirror.example/el/9/?a=1\n" +
			"        https://packagecloud.io/alpacax/alpamon/el/9/$basearch\n",
		"docker-ce.repo": yumThirdPartyRepoFile,
	})

	assert.Equal(t, []string{
		"--setopt=*.skip_if_unavailable=True",
		"--setopt=alpacax_alpamon.skip_if_unavailable=False",
	}, yumSkipUnavailableSetopts())
}

func TestYumSkipUnavailableSetopts_ReadsEveryReposDir(t *testing.T) {
	etc, distro := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(etc, "fedora.repo"), []byte("[fedora]\nmetalink=https://mirrors.fedoraproject.org/metalink\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(distro, "alpacax_alpamon.repo"), []byte(yumAlpamonRepoFile), 0o644))
	setYumReposDirs(t, etc, filepath.Join(t.TempDir(), "missing"), distro)

	got := yumSkipUnavailableSetopts()

	assert.Equal(t, []string{
		"--setopt=*.skip_if_unavailable=True",
		"--setopt=alpacax_alpamon.skip_if_unavailable=False",
		"--setopt=alpacax_alpamon-source.skip_if_unavailable=False",
	}, got)
}
