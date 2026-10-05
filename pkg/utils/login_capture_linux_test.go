//go:build linux

package utils

import (
	"encoding/json"
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
// configuration, where there is one, is fully readable by the PAMServiceName
// scan: the stock Include of the drop-in directory must not turn hooks.sshd
// into unreadable.
func TestStockSSHDConfigIsFollowed(t *testing.T) {
	c := newLoginCaptureCollector("/")
	_, files := c.sshdFingerprint("")
	if len(files) == 0 {
		t.Log("no sshd configuration on this host")
		return
	}
	for _, f := range files {
		data, _, _, ok := c.readSmallFile(f, fileStamp{})
		if !assert.True(t, ok, "read %s", f) {
			continue
		}
		t.Logf("sshd config %s: uncertain=%v", f, sshdConfigServiceUncertain(string(data)))
		assert.False(t, sshdConfigServiceUncertain(string(data)), "stock %s must not read as uncertain", f)
	}
}
