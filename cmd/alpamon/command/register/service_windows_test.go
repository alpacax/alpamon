//go:build windows

package register

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestQuoteServicePath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty input is returned as-is",
			in:   "",
			want: "",
		},
		{
			name: "no-whitespace path is returned unchanged",
			in:   `C:\alpamon\alpamon.exe`,
			want: `C:\alpamon\alpamon.exe`,
		},
		{
			name: "space in path triggers wrapping",
			in:   `C:\Program Files\alpamon\alpamon.exe`,
			want: `"C:\Program Files\alpamon\alpamon.exe"`,
		},
		{
			name: "tab in path triggers wrapping",
			in:   "C:\\with\ttab\\alpamon.exe",
			want: "\"C:\\with\ttab\\alpamon.exe\"",
		},
		{
			name: "already-quoted path is returned unchanged (do not double-quote our own input)",
			in:   `"C:\Program Files\alpamon\alpamon.exe"`,
			want: `"C:\Program Files\alpamon\alpamon.exe"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := quoteServicePath(tc.in)
			require.Equal(t, tc.want, got, "quoteServicePath(%q)", tc.in)
		})
	}
}

// TestStartService_BinaryPathNotDoubleEncoded exercises the production
// composition of quoteServicePath + mgr.CreateService +
// normalizeServiceBinaryPath against the real local SCM, and asserts
// that the resulting ImagePath registry value is the canonical form
// wrapped once in double quotes. This is the regression gate for the
// double-encoding bug fixed by normalizeServiceBinaryPath — the bug
// only reproduces against the real SCM (mgr.CreateService applies
// syscall.EscapeArg internally, which we cannot observe via a unit
// test of helpers).
//
// Skipped if the test process can't open the SCM with create
// privileges (i.e. not running as Administrator). GitHub-hosted
// windows-latest runners are admin so CI does exercise this path.
// Connect failures other than ACCESS_DENIED (e.g. SCM/RPC issues) are
// surfaced via require.NoError rather than silently skipped, so CI does not
// mask real regressions behind the elevation skip.
func TestStartService_BinaryPathNotDoubleEncoded(t *testing.T) {
	m, err := mgr.Connect()
	if err != nil {
		var errno windows.Errno
		if errors.As(err, &errno) && errno == windows.ERROR_ACCESS_DENIED {
			t.Skipf("requires Administrator + SCM access (mgr.Connect: %v)", err)
		}
		require.NoError(t, err, "mgr.Connect failed")
	}
	t.Cleanup(func() { _ = m.Disconnect() })

	// Sentinel name to avoid colliding with a real alpamon install or
	// a parallel test invocation. Long enough to make accidental
	// reuse practically impossible.
	svcName := fmt.Sprintf("alpamon-test-%d-%d", os.Getpid(), time.Now().UnixNano())

	// The bug only fires on whitespace-containing paths, because
	// quoteServicePath only wraps those. Force the condition by
	// constructing a path with a space under t.TempDir(); the file
	// does not need to exist — SCM stores BinaryPathName at create
	// time and validates it only at service start, which we never
	// invoke here.
	binPath := filepath.Join(t.TempDir(), "with space", "alpamon.exe")
	serviceBinPath := quoteServicePath(binPath)

	s, err := m.CreateService(
		svcName,
		serviceBinPath,
		mgr.Config{
			DisplayName:  "Alpamon Test Service (transient)",
			StartType:    mgr.StartManual,
			ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
			ErrorControl: mgr.ErrorNormal,
		},
	)
	if err != nil {
		// mgr.Connect can succeed with read-only SCM access on some
		// hosts (e.g. limited local accounts), so CreateService is the
		// real privilege gate. Treat ACCESS_DENIED here as a skip to
		// match the docstring's intent and avoid hard-failing
		// non-Administrator local runs.
		var errno windows.Errno
		if errors.As(err, &errno) && errno == windows.ERROR_ACCESS_DENIED {
			t.Skipf("requires Administrator + SCM create access (CreateService: %v)", err)
		}
		require.NoError(t, err, "CreateService")
	}
	t.Cleanup(func() {
		_ = s.Delete()
		_ = s.Close()
	})

	err = normalizeServiceBinaryPath(s, serviceBinPath)
	require.NoError(t, err, "normalizeServiceBinaryPath")

	// Read the stored ImagePath directly from the registry — sc.exe
	// qc and s.Config() both go back through the SCM API, which can
	// be lossy in either direction. The registry is the ground truth
	// for what SCM will hand to CreateProcess at start time.
	keyPath := `SYSTEM\CurrentControlSet\Services\` + svcName
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	require.NoError(t, err, "open registry key %q", keyPath)
	defer func() { _ = k.Close() }()

	imagePath, _, err := k.GetStringValue("ImagePath")
	require.NoError(t, err, "read ImagePath value")

	assert.Equal(t, serviceBinPath, imagePath, "ImagePath")
	assert.True(t, strings.HasPrefix(imagePath, `"`), "ImagePath %q does not start with a literal quote", imagePath)
	assert.NotContains(t, imagePath, `\"`, "ImagePath contains backslash-escaped quote: double-encoding regressed")
}
