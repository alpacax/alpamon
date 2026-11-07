//go:build linux

package exposure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The host fixtures under testdata/exposure/hosts are the wire contract's
// goldens: each case is a fake host root plus case.json (what git cannot
// carry: modes, owners, the process table, accounting records) and
// expected.json, the exact body alpamon sends for it. Regenerate with
// EXPOSURE_UPDATE_GOLDEN=1.

// goldenObservedAt is the read time every golden is sealed with.
const goldenObservedAt = "2026-11-07T19:30:00Z"

// fixtureMtime predates every fixture process's start, so a master sshd
// corresponds to the configuration the case ships.
var fixtureMtime = time.Unix(1577836800, 0)

type caseProcess struct {
	PID   int      `json:"pid"`
	PPID  int      `json:"ppid"`
	Comm  string   `json:"comm"`
	Argv  []string `json:"argv"`
	Start int64    `json:"start"`
}

type caseLogin struct {
	User string `json:"user"`
	UID  int    `json:"uid"`
	Line string `json:"line"`
	Host string `json:"host"`
	Time string `json:"time"`
}

type caseSpec struct {
	Hostname    string            `json:"hostname"`
	SSHD        string            `json:"sshd"`
	Btime       int64             `json:"btime"`
	Processes   []caseProcess     `json:"processes"`
	Modes       map[string]string `json:"modes"`
	Owners      map[string]uint32 `json:"owners"`
	Unreadable  []string          `json:"unreadable"`
	Wtmp        []caseLogin       `json:"wtmp"`
	Lastlog     []caseLogin       `json:"lastlog"`
	Canaries    []string          `json:"canaries"`
	NeverOpened []string          `json:"never_opened"`
}

// metaFiles are case files that are not part of the host root.
var metaFiles = map[string]bool{"case.json": true, "expected.json": true, "sshd-T.txt": true}

func loadCase(t *testing.T, dir string) caseSpec {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "case.json"))
	require.NoError(t, err)
	var spec caseSpec
	require.NoError(t, json.Unmarshal(raw, &spec))
	return spec
}

func parseTime(t *testing.T, s string) int64 {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return tm.Unix()
}

func putCString(dst []byte, s string) { copy(dst, s) }

func encodeWtmp(t *testing.T, logins []caseLogin) []byte {
	var out []byte
	for i, l := range logins {
		rec := make([]byte, utmpSize)
		binary.LittleEndian.PutUint16(rec[0:2], utmpUserProcess)
		binary.LittleEndian.PutUint32(rec[4:8], uint32(1000+i))
		putCString(rec[8:40], l.Line)
		putCString(rec[44:76], l.User)
		putCString(rec[76:332], l.Host)
		binary.LittleEndian.PutUint32(rec[340:344], uint32(parseTime(t, l.Time)))
		out = append(out, rec...)
		// A logout record for the same line, which the reduction ignores.
		dead := make([]byte, utmpSize)
		binary.LittleEndian.PutUint16(dead[0:2], 8)
		putCString(dead[8:40], l.Line)
		binary.LittleEndian.PutUint32(dead[340:344], uint32(parseTime(t, l.Time)+60))
		out = append(out, dead...)
	}
	return out
}

func encodeLastlog(t *testing.T, logins []caseLogin) []byte {
	maxUID := 0
	for _, l := range logins {
		maxUID = max(maxUID, l.UID)
	}
	out := make([]byte, (maxUID+1)*lastlogSize)
	for _, l := range logins {
		rec := out[l.UID*lastlogSize : (l.UID+1)*lastlogSize]
		binary.LittleEndian.PutUint32(rec[0:4], uint32(parseTime(t, l.Time)))
		putCString(rec[4:36], l.Line)
		putCString(rec[36:292], l.Host)
	}
	return out
}

// syncAccounting writes or checks the committed wtmp and lastlog binaries
// against the case's records.
func syncAccounting(t *testing.T, dir string, spec caseSpec) {
	t.Helper()
	for name, want := range map[string][]byte{
		"var/log/wtmp":    encodeWtmp(t, spec.Wtmp),
		"var/log/lastlog": encodeLastlog(t, spec.Lastlog),
	} {
		p := filepath.Join(dir, name)
		if len(want) == 0 || (name == "var/log/lastlog" && len(spec.Lastlog) == 0) {
			continue
		}
		if updateGolden {
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
			require.NoError(t, os.WriteFile(p, want, 0o644))
			continue
		}
		got, err := os.ReadFile(p)
		require.NoError(t, err, "committed %s is missing; regenerate with EXPOSURE_UPDATE_GOLDEN=1", name)
		require.True(t, bytes.Equal(want, got), "committed %s does not match case.json", name)
	}
}

// buildHost copies a case's host root into a temporary directory with the
// modes and times git cannot carry, and writes its process table.
func buildHost(t *testing.T, dir string, spec caseSpec) (string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	require.NoError(t, os.Mkdir(root, 0o755))
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." || metaFiles[rel] {
			return nil
		}
		dst := filepath.Join(root, rel)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(target, dst)
		case info.IsDir():
			return os.Mkdir(dst, 0o755)
		default:
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(dst, data, 0o644)
		}
	})
	require.NoError(t, err)
	// Normalize modes, then apply the case's, then fix every mtime.
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink != 0 {
			return err
		}
		if d.IsDir() {
			return os.Chmod(p, 0o755)
		}
		return os.Chmod(p, 0o644)
	}))
	for rel, mode := range spec.Modes {
		m, err := strconv.ParseUint(mode, 8, 32)
		require.NoError(t, err)
		require.NoError(t, os.Chmod(filepath.Join(root, rel), os.FileMode(m)))
	}
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink != 0 {
			return err
		}
		return os.Chtimes(p, fixtureMtime, fixtureMtime)
	}))

	proc := filepath.Join(base, "proc")
	require.NoError(t, os.Mkdir(proc, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(proc, "stat"), []byte("cpu  1 2 3 4\nbtime "+strconv.FormatInt(spec.Btime, 10)+"\n"), 0o644))
	for _, p := range spec.Processes {
		pd := filepath.Join(proc, strconv.Itoa(p.PID))
		require.NoError(t, os.Mkdir(pd, 0o755))
		ticks := (p.Start - spec.Btime) * clockTicks
		stat := strconv.Itoa(p.PID) + " (" + p.Comm + ") S " + strconv.Itoa(p.PPID) +
			" 1 1 0 -1 4194560 100 0 0 0 1 1 0 0 20 0 1 0 " + strconv.FormatInt(ticks, 10) + " 1000 100\n"
		require.NoError(t, os.WriteFile(filepath.Join(pd, "stat"), []byte(stat), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(pd, "cmdline"), []byte(strings.Join(p.Argv, "\x00")+"\x00"), 0o644))
	}
	return root, proc
}

// caseOptions are the collector options for a built case.
func caseOptions(t *testing.T, dir string, spec caseSpec, root, proc string) collectorOptions {
	t.Helper()
	var out []byte
	switch spec.SSHD {
	case "missing", "fail":
	default:
		var err error
		out, err = os.ReadFile(filepath.Join(dir, spec.SSHD))
		require.NoError(t, err)
	}
	return collectorOptions{
		root:     root,
		procRoot: proc,
		hostname: func() string { return spec.Hostname },
		runSSHD: func(context.Context) sshdRun {
			switch spec.SSHD {
			case "missing":
				return sshdRun{notInstalled: true}
			case "fail":
				return sshdRun{}
			}
			return sshdRun{ok: true, out: bytes.Clone(out)}
		},
		mapOwner: func(p string, uid uint32) uint32 {
			if o, ok := spec.Owners[p]; ok {
				return o
			}
			return 0
		},
		budget: categoryBudget,
	}
}

// captureLogs sends the global logger to a buffer for the test.
func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev, prevLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(buf).Level(zerolog.DebugLevel)
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() {
		log.Logger = prev
		zerolog.SetGlobalLevel(prevLevel)
	})
	return buf
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// recordOpens installs testHookOpen for the test: it records every path
// opened and fails the listed ones with EACCES.
func recordOpens(t *testing.T, unreadable []string) func() []string {
	t.Helper()
	var mu sync.Mutex
	var opened []string
	deny := map[string]bool{}
	for _, p := range unreadable {
		deny[p] = true
	}
	testHookOpen = func(p string) error {
		mu.Lock()
		defer mu.Unlock()
		opened = append(opened, p)
		if deny[p] {
			return unix.EACCES
		}
		return nil
	}
	t.Cleanup(func() { testHookOpen = nil })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(opened)
	}
}

// collectCase reads a case and returns the sealed body with the report.
func collectCase(t *testing.T, name string) ([]byte, *Report, caseSpec, string, []string) {
	t.Helper()
	dir := filepath.Join(fixturesDir, "hosts", name)
	spec := loadCase(t, dir)
	syncAccounting(t, dir, spec)
	root, proc := buildHost(t, dir, spec)
	logs := captureLogs(t)
	opened := recordOpens(t, spec.Unreadable)
	c := newCollector(caseOptions(t, dir, spec, root, proc))
	r := c.collect(context.Background())
	r.ObservedAt = goldenObservedAt
	body, err := finalize(r)
	require.NoError(t, err)
	return body, r, spec, logs.String(), opened()
}

func caseNames(t *testing.T) []string {
	entries, err := os.ReadDir(filepath.Join(fixturesDir, "hosts"))
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	require.NotEmpty(t, names)
	return names
}

// TestGoldenHosts collects every fixture host and holds the body to its
// expected.json byte for byte, and the hash to one recomputed from the
// golden itself by the canonical rules.
func TestGoldenHosts(t *testing.T) {
	for _, name := range caseNames(t) {
		t.Run(name, func(t *testing.T) {
			body, r, spec, logs, opened := collectCase(t, name)
			expectedPath := filepath.Join(fixturesDir, "hosts", name, "expected.json")
			if updateGolden {
				require.NoError(t, os.WriteFile(expectedPath, append(slices.Clone(body), '\n'), 0o644))
			}
			want, err := os.ReadFile(expectedPath)
			require.NoError(t, err)
			assert.Equal(t, string(bytes.TrimSuffix(want, []byte("\n"))), string(body))
			assert.Equal(t, goldenHash(t, want), r.Hash)
			if name == "ubuntu-default" {
				for _, category := range []string{catAccounts, catSudo, catKeys} {
					assert.Equal(t, Coverage{Status: coverageCovered, Reasons: []string{}}, r.Categories[category])
				}
			}
			if name == "systemd-homed" {
				assert.Equal(t, Coverage{Status: coveragePartial, Reasons: []string{reasonExternalSource}}, r.Categories[catAccounts])
				assert.Contains(t, r.External, External{Kind: externalNSSAccounts, Scope: "global", Sources: []string{"systemd"}})
			}

			// Leak canaries, on every case: never in the body, the hash
			// input or the log output.
			input, err := hashInput(r)
			require.NoError(t, err)
			for _, canary := range append([]string{"LEAKCANARY"}, spec.Canaries...) {
				assert.NotContains(t, string(body), canary)
				assert.NotContains(t, string(input), canary)
				assert.NotContains(t, logs, canary)
			}
			for _, p := range spec.NeverOpened {
				assert.NotContains(t, opened, p, "trust file opened with its authentication off")
			}
			assertClosedReasons(t, body)
		})
	}
}

// goldenHash recomputes the hash from a golden body: canonical JSON with
// observed_at and hash removed.
func goldenHash(t *testing.T, body []byte) string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var tree map[string]any
	require.NoError(t, dec.Decode(&tree))
	delete(tree, "observed_at")
	delete(tree, "hash")
	canon, err := appendCanonical(nil, tree)
	require.NoError(t, err)
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// A keys worker abandoned on a hung read keeps reading the sshd policy it
// was given while the report is assembled and encoded. Nothing may write to
// what it reads; the race detector checks the overlap.
func TestAbandonedWorkerSharesNothingWritable(t *testing.T) {
	dir := filepath.Join(fixturesDir, "hosts", "match-blocks")
	spec := loadCase(t, dir)
	root, proc := buildHost(t, dir, spec)
	release := make(chan struct{})
	var once sync.Once
	testHookRead = func(p string) {
		if strings.HasSuffix(p, "/.ssh/authorized_keys") || strings.HasSuffix(p, "/.ssh/authorized_keys2") {
			once.Do(func() { <-release })
		}
	}
	t.Cleanup(func() { testHookRead = nil })
	// Make one key file exist so the hook is reached.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "home/deploy/.ssh"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "home/deploy/.ssh/authorized_keys"), []byte("\n"), 0o644))
	opts := caseOptions(t, dir, spec, root, proc)
	opts.budget = 200 * time.Millisecond
	r := newCollector(opts).collect(context.Background())
	assert.Contains(t, r.Categories[catKeys].Reasons, reasonTimeout)
	assert.Equal(t, coverageUnknown, r.Categories[catKeys].Status)

	var wg sync.WaitGroup
	wg.Go(func() { close(release) })
	for range 20 {
		_, err := finalize(r)
		require.NoError(t, err)
	}
	wg.Wait()
}
