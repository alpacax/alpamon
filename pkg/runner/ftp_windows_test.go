//go:build windows

// Windows-specific coverage for parsePath after the #311 fix. The
// previous home-directory containment was removed from parsePath
// because alpamon runs as SYSTEM on Windows (privilege demotion is
// stubbed) and the lexical guard provided no real protection. These
// tests document the new behavior: parsePath returns the cleaned
// absolute Windows path for any input the OS itself can resolve.

package runner

import (
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestFtpClient(home string) *FtpClient {
	return &FtpClient{
		homeDirectory:    home,
		workingDirectory: home,
	}
}

func TestParsePath_Windows(t *testing.T) {
	fc := newTestFtpClient(`C:\Users\test`)

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{
			// The bug reproduced: a system path outside the operator's
			// mapped home directory used to return "path escapes home
			// directory". After the fix, parsePath returns the native
			// Windows form unchanged.
			name: "absolute outside home (system root)",
			path: "/C:/Windows/System32/drivers/etc/hosts",
			want: `C:\Windows\System32\drivers\etc\hosts`,
		},
		{
			// Regression guard: paths under home still resolve correctly.
			name: "absolute inside home",
			path: "/C:/Users/test/Desktop/note.txt",
			want: `C:\Users\test\Desktop\note.txt`,
		},
		{
			name: "tilde expands to working directory",
			path: "~/Desktop/x.txt",
			want: `C:\Users\test\Desktop\x.txt`,
		},
		{
			name: "relative path joined to working directory",
			path: "Desktop/x.txt",
			want: `C:\Users\test\Desktop\x.txt`,
		},
		{
			// FromWirePath normalizes /C: to the drive root C:\.
			name: "drive-letter root normalization",
			path: "/C:",
			want: `C:\`,
		},
		{
			// Different drive: blocked pre-fix by the home guard, allowed
			// post-fix.
			name: "absolute on different drive",
			path: "/D:/Data/export.csv",
			want: `D:\Data\export.csv`,
		},
		{
			// Dot-dot in the wire path is collapsed by filepath.Clean.
			// Post-fix this is no longer rejected as an escape.
			name: "dot-dot in wire path is resolved",
			path: "/C:/Users/test/../foo.txt",
			want: `C:\Users\foo.txt`,
		},
		{
			// Security regression guard: null-byte rejection at the top
			// of parsePath remains in place.
			name:    "null byte rejected",
			path:    "/C:/foo\x00.txt",
			wantErr: true,
		},
		{
			// Edge case unchanged by this fix.
			name:    "only null byte",
			path:    "\x00",
			wantErr: true,
		},
		{
			// Security regression: a wire path "//evil/share/..."
			// translates to "\\evil\share\..." (UNC) via FromSlash.
			// alpamon (SYSTEM) opening this would attempt to
			// authenticate to an attacker-controlled SMB server —
			// NTLM hash leak vector. Reject at parsePath.
			name:    "UNC path (wire form) rejected",
			path:    "//evil.attacker.com/share/payload.exe",
			wantErr: true,
		},
		{
			name:    "UNC path (native form) rejected",
			path:    `\\evil.attacker.com\share\payload.exe`,
			wantErr: true,
		},
		{
			// Security regression: local device namespace gives raw
			// disk read/write to SYSTEM. Reject.
			name:    "local device namespace rejected",
			path:    "//./PHYSICALDRIVE0",
			wantErr: true,
		},
		{
			// Security regression: extended-length namespace bypasses
			// path canonicalization. Reject.
			name:    "extended-length namespace rejected",
			path:    `\\?\C:\Windows\System32\config\SAM`,
			wantErr: true,
		},
		{
			// Security regression: extended-length UNC is the UNC
			// variant of the above.
			name:    "extended-length UNC rejected",
			path:    `\\?\UNC\evil\share\x`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fc.parsePath(tc.path)
			if tc.wantErr {
				require.Error(t, err, "parsePath(%q) expected error, got %q", tc.path, got)
				return
			}
			require.NoError(t, err, "parsePath(%q) unexpected error", tc.path)
			require.Equal(t, tc.want, got, "parsePath(%q)", tc.path)
		})
	}
}

func TestParsePath_Windows_NullByteErrorMessage(t *testing.T) {
	fc := newTestFtpClient(`C:\Users\test`)

	_, err := fc.parsePath("/C:/foo\x00.txt")
	require.Error(t, err, "expected error for null-byte path")
	assert.ErrorContains(t, err, "null byte")
}

// TestNewFtpClient_Windows_EmptyHomeReturnsNil verifies that the
// predictability guard in NewFtpClient still rejects sessions with no
// home directory on Windows. Although containment is no longer the
// rationale, an empty home would make relative paths resolve against
// the service CWD, producing confusing results, so the session is
// refused at construction time.
func TestNewFtpClient_Windows_EmptyHomeReturnsNil(t *testing.T) {
	cfg := FtpConfigData{
		URL:           "ws://example.com/test",
		ServerURL:     "https://example.com",
		HomeDirectory: "",
		Logger:        logger.NewFtpLogger(),
	}

	client := NewFtpClient(cfg)
	require.Nil(t, client, "expected nil client for empty HomeDirectory")
}

// TestNewFtpClient_Windows_NonEmptyHomeReturnsClient sanity-checks the
// other branch: a valid HomeDirectory yields a usable FtpClient.
func TestNewFtpClient_Windows_NonEmptyHomeReturnsClient(t *testing.T) {
	cfg := FtpConfigData{
		URL:           "ws://example.com/test",
		ServerURL:     "https://example.com",
		HomeDirectory: "/C:/Users/test",
		Logger:        logger.NewFtpLogger(),
	}

	client := NewFtpClient(cfg)
	require.NotNil(t, client, "expected non-nil client for valid HomeDirectory")
	assert.Equal(t, `C:\Users\test`, client.homeDirectory)
}
