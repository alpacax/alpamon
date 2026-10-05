//go:build linux

package utils

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetLoginCaptureOnThisHost runs the real collector against the host it
// runs on, read-only. What it finds depends on the host, so only the shape is
// checked: a block always comes back on Linux, with schema 1 and the three
// required hooks filled in.
func TestGetLoginCaptureOnThisHost(t *testing.T) {
	got := GetLoginCapture()
	if !assert.NotNil(t, got) {
		return
	}
	data, err := json.Marshal(got)
	assert.NoError(t, err)
	t.Logf("login_capture on this host: %s", data)
	t.Logf("libpam module directory on this host: %q", newLoginCaptureCollector("/").libpamModuleDir())
	assert.Equal(t, 1, got.Schema)
	assert.Contains(t, []string{PAMModulePresent, PAMModuleMissing}, got.PAMModule)
	for _, hook := range []string{got.Hooks.SSHD, got.Hooks.Login, got.Hooks.Su} {
		assert.Contains(t, []string{HookRegistered, HookMissing, HookNotApplicable, HookUnreadable}, hook)
	}
}

// TestStockSSHDConfigIsFollowed checks that the host's own sshd
// configuration, where there is one, does not by itself turn hooks.sshd into
// unreadable: the stock Include lines are followed and every file is read.
// Files only root can read are skipped when the test runs unprivileged; the
// agent runs as root.
func TestStockSSHDConfigIsFollowed(t *testing.T) {
	c := newLoginCaptureCollector("/")
	_, files := c.sshdFingerprint("")
	if len(files) == 0 {
		t.Log("no sshd configuration on this host")
		return
	}
	if os.Geteuid() != 0 {
		c.readFile = func(name string) ([]byte, error) {
			data, err := os.ReadFile(name)
			if errors.Is(err, fs.ErrPermission) {
				t.Logf("sshd config %s: readable by root only, skipped", name)
				return nil, nil
			}
			return data, err
		}
	}
	seen := make(map[string]bool)
	for _, f := range files {
		uncertain := c.sshdConfigUncertain(f, 0, seen)
		t.Logf("sshd config %s: uncertain=%v", f, uncertain)
		assert.False(t, uncertain, "stock %s must not read as uncertain", f)
	}
}
