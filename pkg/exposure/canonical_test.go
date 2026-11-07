package exposure

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalForm(t *testing.T) {
	type inner struct {
		Z      string   `json:"z"`
		A      *string  `json:"a"`
		List   []string `json:"list"`
		Null   []string `json:"null" nullable:"true"`
		Number int      `json:"number"`
	}
	got, err := encodeValue(inner{Z: "<&> \"q\" \\ \n\t\x01 é"})
	require.NoError(t, err)
	assert.Equal(t, `{"a":null,"list":[],"null":null,"number":0,"z":"<&> \"q\" \\ \n\t\u0001 é"}`, string(got))
}

func TestCanonicalFillsNilSlicesInsideMaps(t *testing.T) {
	r := newTestReport()
	r.Categories[catKeys] = Coverage{Status: coverageCovered}
	body, err := encodeValue(*r)
	require.NoError(t, err)
	assert.Contains(t, string(body), `"keys":{"reasons":[],"status":"covered"}`)
}

func newTestReport() *Report {
	r := &Report{
		SchemaVersion: SchemaVersion,
		ObservedAt:    "2026-11-07T19:30:00Z",
		Scope:         Scope{OS: "linux", Protocol: "ssh"},
		Categories:    map[string]Coverage{},
		SSHD:          SSHD{Daemon: Daemon{Correspondence: "unresolved"}},
	}
	for _, n := range categoryNames {
		r.Categories[n] = Coverage{Status: coverageCovered}
	}
	return r
}

// TestCanonicalGolden pins the canonical bytes and hash of a small report.
// The hash input is the body with observed_at and hash removed.
func TestCanonicalGolden(t *testing.T) {
	r := newTestReport()
	r.Accounts = []Account{{
		Username: "deploy", UID: 1001, Shell: ptr("/bin/bash"), LoginShell: true,
		Groups: []string{"deploy", "wheel"},
		Shadow: Shadow{Status: shadowRead, PasswordState: passwordLocked, LastChangeDays: ptr(int64(20123))},
		Home:   Home{Status: statusRead, StrictModesOK: ptr(true)},
		Sudo: AccountSudo{Complete: true, Grants: []Grant{{
			Source: "/etc/sudoers", Via: "group:wheel", Runas: "ALL:ALL", Commands: "all", NoPasswd: true,
		}}},
	}}
	body, err := finalize(r)
	require.NoError(t, err)

	const wantBody = `{"accounts":[{"groups":["deploy","wheel"],"home":{"status":"read","strict_modes_ok":true},"key_files":[],"last_pty_login":null,"login_shell":true,"principals_files":[],"shadow":{"expire_days":null,"inactive_days":null,"last_change_days":20123,"password_state":"locked","status":"read"},"shell":"/bin/bash","sudo":{"complete":true,"grants":[{"args_restricted":false,"command_paths":[],"commands":"all","nopasswd":true,"runas":"ALL:ALL","source":"/etc/sudoers","via":"group:wheel"}],"reasons":[]},"trust_files":[],"uid":1001,"username":"deploy"}],"categories":{"accounts":{"reasons":[],"status":"covered"},"certificates":{"reasons":[],"status":"covered"},"keys":{"reasons":[],"status":"covered"},"passwords":{"reasons":[],"status":"covered"},"pty_history":{"reasons":[],"status":"covered"},"sshd":{"reasons":[],"status":"covered"},"sudo":{"reasons":[],"status":"covered"},"trust":{"reasons":[],"status":"covered"}},"external":[],"hash":"HASH","observed_at":"2026-11-07T19:30:00Z","schema_version":1,"scope":{"os":"linux","protocol":"ssh"},"sshd":{"daemon":{"config_path_matches":null,"correspondence":"unresolved"},"effective":null,"match_blocks":[]},"system_trust":[],"user_ca":null}`
	input := strings.Replace(wantBody, `"hash":"HASH","observed_at":"2026-11-07T19:30:00Z",`, "", 1)
	sum := sha256.Sum256([]byte(input))
	wantHash := "sha256:" + hex.EncodeToString(sum[:])
	assert.Equal(t, strings.Replace(wantBody, "HASH", wantHash, 1), string(body))
	assert.Equal(t, wantHash, r.Hash)
	assert.Equal(t, "sha256:f9c5da042e38d711af571e1184d342af310714bae5088e8f22323a3ada58e13b", wantHash, "pinned hash of the golden input")

	gotInput, err := hashInput(r)
	require.NoError(t, err)
	assert.Equal(t, input, string(gotInput))
}

func TestHashIgnoresObservedAtOnly(t *testing.T) {
	a, b := newTestReport(), newTestReport()
	b.ObservedAt = "2030-01-01T00:00:00Z"
	_, err := finalize(a)
	require.NoError(t, err)
	_, err = finalize(b)
	require.NoError(t, err)
	assert.Equal(t, a.Hash, b.Hash)

	b.Accounts = []Account{{Username: "x"}}
	_, err = finalize(b)
	require.NoError(t, err)
	assert.NotEqual(t, a.Hash, b.Hash)
}

// TestReportCap fills a report past 2 MiB and checks that it is cut in the
// fixed order, marked limit_exceeded, still sealed and still sent.
func TestReportCap(t *testing.T) {
	r := newTestReport()
	for i := range 400 {
		var keys []Key
		for j := range 40 {
			keys = append(keys, Key{Fingerprint: "SHA256:" + strings.Repeat("k", 43) + string(rune('a'+j%26)), Type: "ssh-ed25519", Bits: 256,
				Authorizations: []Authorization{{Count: 1, Role: "user_key", Comment: ptr(strings.Repeat("c", 100)), Options: []string{}}}})
		}
		r.Accounts = append(r.Accounts, Account{
			Username: "user" + strings.Repeat("0", 3-len(itoa(i))) + itoa(i), UID: uint32(1000 + i),
			Shadow: Shadow{Status: shadowRead, PasswordState: passwordNone},
			Home:   Home{Status: statusRead},
			KeyFiles: []KeyFile{{Envelope: Envelope{Path: "/home/u/.ssh/authorized_keys", Status: statusRead, Complete: true, Reasons: []string{}},
				Keys: keys}},
			Sudo: AccountSudo{Complete: true},
		})
	}
	full, err := encodeValue(*r)
	require.NoError(t, err)
	require.Greater(t, len(full), maxReportBytes)

	body, err := finalize(r)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(body), maxReportBytes)
	assert.Equal(t, coveragePartial, r.Categories[catKeys].Status)
	assert.Contains(t, r.Categories[catKeys].Reasons, reasonLimitExceeded)
	assert.Equal(t, coverageCovered, r.Categories[catAccounts].Status, "accounts are cut only after every other category")
	assert.Len(t, r.Accounts, 400)
	cut := r.Accounts[len(r.Accounts)-1].KeyFiles[0]
	assert.Empty(t, cut.Keys)
	assert.False(t, cut.Complete)
	assert.Contains(t, cut.Reasons, reasonLimitExceeded)
	assert.NotEmpty(t, r.Accounts[0].KeyFiles[0].Keys, "cutting runs from the last account")
	input, err := hashInput(r)
	require.NoError(t, err)
	sum := sha256.Sum256(input)
	assert.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), r.Hash, "the hash covers the capped report")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}
