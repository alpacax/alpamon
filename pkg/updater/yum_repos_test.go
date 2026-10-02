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

// TestMain points YumReposDirs at an empty temp dir and YumConfFiles at none, so no test reads the host's yum config.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "alpamon-yum-repos")
	if err != nil {
		panic(err)
	}
	YumReposDirs = []string{dir}
	YumConfFiles = []string{filepath.Join(dir, "missing.conf")}
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

func setYumConfFiles(t *testing.T, paths ...string) {
	t.Helper()
	orig := YumConfFiles
	YumConfFiles = paths
	t.Cleanup(func() { YumConfFiles = orig })
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
	}, yumSkipUnavailableSetopts(scanYumRepos()))
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
	}, yumSkipUnavailableSetopts(scanYumRepos()))
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
	}, yumSkipUnavailableSetopts(scanYumRepos()))
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
	}, yumSkipUnavailableSetopts(scanYumRepos()))
}

func TestYumSkipUnavailableSetopts_ReadsEveryReposDir(t *testing.T) {
	etc, distro := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(etc, "fedora.repo"), []byte("[fedora]\nmetalink=https://mirrors.fedoraproject.org/metalink\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(distro, "alpacax_alpamon.repo"), []byte(yumAlpamonRepoFile), 0o644))
	setYumReposDirs(t, etc, filepath.Join(t.TempDir(), "missing"), distro)

	got := yumSkipUnavailableSetopts(scanYumRepos())

	assert.Equal(t, []string{
		"--setopt=*.skip_if_unavailable=True",
		"--setopt=alpacax_alpamon.skip_if_unavailable=False",
		"--setopt=alpacax_alpamon-source.skip_if_unavailable=False",
	}, got)
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
}

func TestYumSkipUnavailableSetopts_ReadsOnlyTheReposdirTheMainConfigSets(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "default", "alpacax_alpamon.repo"), yumAlpamonRepoFile)
	writeFile(t, filepath.Join(root, "a", "alpacax_alpamon-dev.repo"), "[alpacax_alpamon-dev]\nbaseurl=https://packagecloud.io/alpacax/alpamon-dev/el/9/$basearch\n")
	writeFile(t, filepath.Join(root, "b", "alpacax_alpamon-latest.repo"), "[alpacax_alpamon-latest]\nbaseurl=https://packagecloud.io/alpacax/alpamon-latest/el/9/$basearch\n")
	conf := filepath.Join(root, "dnf.conf")
	writeFile(t, conf, "[main]\ngpgcheck=1\n#reposdir=/nowhere\nreposdir = "+filepath.Join(root, "a")+", "+filepath.Join(root, "b")+"\n")
	setYumReposDirs(t, filepath.Join(root, "default"))
	setYumConfFiles(t, conf)

	got := yumSkipUnavailableSetopts(scanYumRepos())

	assert.Equal(t, []string{
		"--setopt=*.skip_if_unavailable=True",
		"--setopt=alpacax_alpamon-dev.skip_if_unavailable=False",
		"--setopt=alpacax_alpamon-latest.skip_if_unavailable=False",
	}, got, "reposdir replaces the default directories, as yum and dnf read it")
}

func TestYumReposDirs_FallsBackToTheDefaults(t *testing.T) {
	root := t.TempDir()
	for name, conf := range map[string]string{
		"no reposdir":            "[main]\ngpgcheck=1\n",
		"reposdir outside main":  "[main]\ngpgcheck=1\n\n[extra]\nreposdir=/nowhere\n",
		"empty reposdir":         "[main]\nreposdir=\n",
		"commented out reposdir": "[main]\n# reposdir=/nowhere\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dnf.conf")
			writeFile(t, path, conf)
			setYumReposDirs(t, root)
			setYumConfFiles(t, path)

			assert.Equal(t, []string{root}, yumReposDirs())
		})
	}
}

func TestYumReposDirs_ReadsAReposdirContinuedOnIndentedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnf.conf")
	writeFile(t, path, "[main]\nreposdir=/opt/a\n  /opt/b, /opt/c\ngpgcheck=1\n  /opt/not-a-reposdir\n")
	setYumConfFiles(t, path)

	assert.Equal(t, []string{"/opt/a", "/opt/b", "/opt/c"}, yumReposDirs())
}

// TestYumReposDirs_ReadsYumConfWhenDnfConfIsMissing pins yum 3 (CentOS 7), which has no /etc/dnf.
func TestYumReposDirs_ReadsYumConfWhenDnfConfIsMissing(t *testing.T) {
	root := t.TempDir()
	yumConf := filepath.Join(root, "yum.conf")
	writeFile(t, yumConf, "[main]\nreposdir=/opt/repos\n")
	setYumConfFiles(t, filepath.Join(root, "dnf", "dnf.conf"), yumConf)

	assert.Equal(t, []string{"/opt/repos"}, yumReposDirs())
}

// TestYumReposDirs_UsesOnlyTheFirstConfigThatExists pins that yum.conf is not read beside dnf.conf: dnf ignores it.
func TestYumReposDirs_UsesOnlyTheFirstConfigThatExists(t *testing.T) {
	root := t.TempDir()
	dnfConf, yumConf := filepath.Join(root, "dnf.conf"), filepath.Join(root, "yum.conf")
	writeFile(t, dnfConf, "[main]\ngpgcheck=1\n")
	writeFile(t, yumConf, "[main]\nreposdir=/opt/repos\n")
	setYumReposDirs(t, root)
	setYumConfFiles(t, dnfConf, yumConf)

	assert.Equal(t, []string{root}, yumReposDirs())
}

// yumMirrorlistFailure is the tail of what yum 3 prints when a repo's mirrorlist cannot be reached.
func yumMirrorlistFailure(id string) string {
	return " One of the configured repositories failed (Unknown),\n and yum doesn't have enough cached data to continue.\n" +
		"Cannot find a valid baseurl for repo: " + id + "/7/x86_64\n"
}

// fakeYum answers each run with the next result and records the argv it was given.
type fakeYum struct {
	results []fakeYumResult
	argvs   [][]string
}

type fakeYumResult struct {
	code int
	out  string
}

func (f *fakeYum) run(argv ...string) (int, string, error) {
	f.argvs = append(f.argvs, argv)
	r := f.results[min(len(f.argvs), len(f.results))-1]
	return r.code, r.out, nil
}

const yumCentOSRepoFile = `[base]
mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=os
[extras]
mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=extras
`

func TestRunYum_DisablesEachRepoWhoseMirrorlistFails(t *testing.T) {
	writeYumRepos(t, map[string]string{"alpacax_alpamon.repo": yumAlpamonRepoFile, "CentOS-Base.repo": yumCentOSRepoFile})
	yum := &fakeYum{results: []fakeYumResult{
		{1, yumMirrorlistFailure("base")},
		{1, yumMirrorlistFailure("extras")},
		{0, "Updated:\n  alpamon.x86_64 0:9.9.9-1\n"},
	}}

	code, out, err := RunYum(yum.run, "update", "alpamon")

	require.NoError(t, err)
	assert.Equal(t, 0, code)
	strict := []string{
		"--setopt=*.skip_if_unavailable=True",
		"--setopt=alpacax_alpamon.skip_if_unavailable=False",
		"--setopt=alpacax_alpamon-source.skip_if_unavailable=False",
	}
	assert.Equal(t, [][]string{
		append(append([]string{"yum"}, strict...), "update", "-y", "alpamon"),
		append(append([]string{"yum"}, strict...), "--disablerepo=base", "update", "-y", "alpamon"),
		append(append([]string{"yum"}, strict...), "--disablerepo=base", "--disablerepo=extras", "update", "-y", "alpamon"),
	}, yum.argvs)
	assert.Equal(t, "Updated:\n  alpamon.x86_64 0:9.9.9-1\n\nDisabled yum repos whose mirrorlist could not be reached: base, extras.", out)
}

func TestRunYum_DoesNotRetry(t *testing.T) {
	for name, tc := range map[string]struct {
		files  map[string]string
		result fakeYumResult
	}{
		"after success": {
			files:  map[string]string{"alpacax_alpamon.repo": yumAlpamonRepoFile, "CentOS-Base.repo": yumCentOSRepoFile},
			result: fakeYumResult{0, "Cannot find a valid baseurl for repo: base/7/x86_64\n"},
		},
		"when alpamon's own repo fails": {
			files:  map[string]string{"alpacax_alpamon.repo": yumAlpamonRepoFile, "CentOS-Base.repo": yumCentOSRepoFile},
			result: fakeYumResult{1, yumMirrorlistFailure("alpacax_alpamon")},
		},
		"when alpamon's repo does not resolve": {
			files:  map[string]string{"CentOS-Base.repo": yumCentOSRepoFile},
			result: fakeYumResult{1, yumMirrorlistFailure("base")},
		},
		"for a repo no repo file defines": {
			files:  map[string]string{"alpacax_alpamon.repo": yumAlpamonRepoFile},
			result: fakeYumResult{1, yumMirrorlistFailure("base")},
		},
		"for a disabled repo": {
			files:  map[string]string{"alpacax_alpamon.repo": yumAlpamonRepoFile, "CentOS-Base.repo": "[base]\nenabled=0\n"},
			result: fakeYumResult{1, yumMirrorlistFailure("base")},
		},
		"for a failure that names no repo": {
			files:  map[string]string{"alpacax_alpamon.repo": yumAlpamonRepoFile, "CentOS-Base.repo": yumCentOSRepoFile},
			result: fakeYumResult{1, "Error: Nothing to do\n"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			writeYumRepos(t, tc.files)
			yum := &fakeYum{results: []fakeYumResult{tc.result}}

			code, out, err := RunYum(yum.run, "update", "alpamon")

			require.NoError(t, err)
			assert.Equal(t, tc.result.code, code)
			assert.Equal(t, tc.result.out, out)
			assert.Len(t, yum.argvs, 1)
		})
	}
}

// TestRunYum_StopsWhenADisabledRepoIsReportedAgain pins that the loop ends on repeated output instead of spinning.
func TestRunYum_StopsWhenADisabledRepoIsReportedAgain(t *testing.T) {
	writeYumRepos(t, map[string]string{"alpacax_alpamon.repo": yumAlpamonRepoFile, "CentOS-Base.repo": yumCentOSRepoFile})
	yum := &fakeYum{results: []fakeYumResult{{1, yumMirrorlistFailure("base")}}}

	code, out, _ := RunYum(yum.run, "update", "alpamon")

	assert.Equal(t, 1, code)
	assert.Len(t, yum.argvs, 2)
	assert.Contains(t, out, "Disabled yum repos whose mirrorlist could not be reached: base.")
}
