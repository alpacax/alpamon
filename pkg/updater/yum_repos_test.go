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

func writeYumRepos(t *testing.T, files map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644))
	}
	orig := YumReposDirs
	YumReposDirs = []string{dir}
	t.Cleanup(func() { YumReposDirs = orig })
}

func TestYumSkipUnavailableSetopts_ReadsEnabledLikeYum(t *testing.T) {
	writeYumRepos(t, map[string]string{
		"alpacax_alpamon.repo": yumAlpamonRepoFile,
		"extra.repo": "; a comment\n[off-no]\nenabled = No\n\n[off-false]\nenabled=false\n\n" +
			"[on-yes]\nenabled = Yes\n\n[on-true]\nenabled=True\n",
	})

	assert.Equal(t, []string{
		"--setopt=alpacax_alpamon.skip_if_unavailable=False",
		"--setopt=alpacax_alpamon-source.skip_if_unavailable=False",
		"--setopt=on-yes.skip_if_unavailable=True",
		"--setopt=on-true.skip_if_unavailable=True",
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
		"--setopt=alpacax_alpamon.skip_if_unavailable=False",
		"--setopt=alpacax_alpamon-source.skip_if_unavailable=False",
		"--setopt=mirror.skip_if_unavailable=True",
	}, yumSkipUnavailableSetopts())
}

func TestYumSkipUnavailableSetopts_MatchesAlpamonOnAContinuedBaseurlLine(t *testing.T) {
	writeYumRepos(t, map[string]string{
		"alpacax_alpamon.repo": "[alpacax_alpamon]\nbaseurl=https://mirror.example/el/9/?a=1\n" +
			"        https://packagecloud.io/alpacax/alpamon/el/9/$basearch\n",
		"docker-ce.repo": yumThirdPartyRepoFile,
	})

	assert.Equal(t, []string{
		"--setopt=alpacax_alpamon.skip_if_unavailable=False",
		"--setopt=docker-ce-stable.skip_if_unavailable=True",
	}, yumSkipUnavailableSetopts())
}

func TestYumSkipUnavailableSetopts_ReadsEveryReposDir(t *testing.T) {
	etc, distro := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(etc, "alpacax_alpamon.repo"), []byte(yumAlpamonRepoFile), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(distro, "fedora.repo"), []byte("[fedora]\nmetalink=https://mirrors.fedoraproject.org/metalink\n"), 0o644))
	orig := YumReposDirs
	YumReposDirs = []string{etc, filepath.Join(t.TempDir(), "missing"), distro}
	t.Cleanup(func() { YumReposDirs = orig })

	got := yumSkipUnavailableSetopts()

	assert.Equal(t, []string{
		"--setopt=alpacax_alpamon.skip_if_unavailable=False",
		"--setopt=alpacax_alpamon-source.skip_if_unavailable=False",
		"--setopt=fedora.skip_if_unavailable=True",
	}, got)
}
