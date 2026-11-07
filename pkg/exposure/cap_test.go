package exposure

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func capAccount(name string, keys []Key) Account {
	return Account{Username: name, KeyFiles: []KeyFile{{Envelope: Envelope{Path: "/home/" + name + "/.ssh/authorized_keys", Status: statusRead, Complete: true, Reasons: []string{}}, Keys: keys}}, Sudo: AccountSudo{Complete: true, Grants: []Grant{}, Reasons: []string{}}}
}

// Each source obeys the input and entry caps; encoded authorization metadata
// expands enough that one account alone can exceed the entire wire budget.
func TestAccountCapIsolatesOtherAccounts(t *testing.T) {
	var files [2]strings.Builder
	var principals, from []string
	for j := 0; j < 64; j++ {
		principals = append(principals, fmt.Sprintf("p%07d", j))
	}
	for len(strings.Join(from, ",")) < 1000 {
		from = append(from, fmt.Sprintf("h%04d.example.com", len(from)))
	}
	for i := 0; i < 1000; i++ {
		blob := binary.BigEndian.AppendUint32(nil, 11)
		blob = append(blob, "ssh-ed25519"...)
		blob = binary.BigEndian.AppendUint32(blob, 32)
		key := make([]byte, 32)
		binary.BigEndian.PutUint32(key, uint32(i))
		blob = append(blob, key...)
		line := fmt.Sprintf("cert-authority,principals=\"%s\",from=\"%s\" ssh-ed25519 %s %s\n", strings.Join(principals, ","), strings.Join(from, ","), base64.StdEncoding.EncodeToString(blob), strings.Repeat("😀", 128))
		if files[0].Len()+len(line) <= maxReadBytes {
			files[0].WriteString(line)
		} else if files[1].Len()+len(line) <= maxReadBytes {
			files[1].WriteString(line)
		}
	}
	budget := maxKeysPerAccount
	a := capAccount("alice", parseAuthorizedKeys([]byte(files[0].String()), &budget).keys)
	a.KeyFiles = append(a.KeyFiles, KeyFile{Envelope: Envelope{Path: "/home/alice/.ssh/authorized_keys2", Status: statusRead, Complete: true, Reasons: []string{}}, Keys: parseAuthorizedKeys([]byte(files[1].String()), &budget).keys})
	var trust strings.Builder
	for i := 0; i < maxTrustEntries; i++ {
		fmt.Fprintf(&trust, "p%0250d\n", i)
	}
	entries, _, _ := parseK5Login([]byte(trust.String()))
	a.TrustFiles = []TrustFile{{Envelope: Envelope{Path: "/home/alice/.k5login", Status: statusRead, Complete: true, Reasons: []string{}}, Kind: "k5login", Entries: entries}}
	r := newTestReport()
	small := parseAuthorizedKeys([]byte("ssh-ed25519 "+testEd0+" ok\n"), newBudget()).keys
	r.Accounts = []Account{a, capAccount("deploy", small), capAccount("root", small), capAccount("ubuntu", small)}
	pre, err := seal(r)
	require.NoError(t, err)
	require.Greater(t, len(pre), maxReportBytes)
	body, err := finalize(r)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(body), maxReportBytes)
	assert.LessOrEqual(t, encodedLen(r.Accounts[0]), maxAccountBytes)
	for _, a := range r.Accounts[1:] {
		require.Len(t, a.KeyFiles, 1)
		assert.True(t, a.KeyFiles[0].Complete)
		assert.Len(t, a.KeyFiles[0].Keys, 1)
		assert.Empty(t, a.KeyFiles[0].Reasons)
	}
	assert.Contains(t, r.Accounts[0].KeyFiles[0].Reasons, reasonLimitExceeded)
}

func newBudget() *int { b := maxKeysPerAccount; return &b }

func TestAccountCapCutsLargestSourceThenStops(t *testing.T) {
	r := newTestReport()
	keys := parseAuthorizedKeys([]byte("ssh-ed25519 "+testEd0+" ok\n"), newBudget()).keys
	a := capAccount("a", keys)
	a.TrustFiles = []TrustFile{{Envelope: Envelope{Path: "/home/a/.k5login", Status: statusRead, Complete: true}, Entries: make([]TrustEntry, 1200)}}
	for i := range a.TrustFiles[0].Entries {
		a.TrustFiles[0].Entries[i].Principal = ptr(strings.Repeat("a", 256))
	}
	r.Accounts = []Account{a}
	_, err := finalize(r)
	require.NoError(t, err)
	assert.Empty(t, r.Accounts[0].TrustFiles[0].Entries)
	assert.False(t, r.Accounts[0].TrustFiles[0].Complete)
	assert.True(t, r.Accounts[0].KeyFiles[0].Complete)
	assert.NotEmpty(t, r.Accounts[0].KeyFiles[0].Keys)
}

func TestAccountMetadataAlsoRespectsCap(t *testing.T) {
	r := newTestReport()
	a := capAccount("a", nil)
	for i := 0; i < maxGroupsPerAccount; i++ {
		a.Groups = append(a.Groups, fmt.Sprintf("g%0255d", i))
	}
	require.Greater(t, encodedLen(a), maxAccountBytes)
	r.Accounts = []Account{a, capAccount("b", nil)}
	_, err := finalize(r)
	require.NoError(t, err)
	require.Len(t, r.Accounts, 1)
	assert.Equal(t, "b", r.Accounts[0].Username)
	assert.Contains(t, r.Categories[catAccounts].Reasons, reasonLimitExceeded)
}
