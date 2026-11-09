package exposure

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func capAccount(name string, keys []key) account {
	return account{Username: name, KeyFiles: []keyFile{{envelope: envelope{Path: "/home/" + name + "/.ssh/authorized_keys", Status: statusRead, Complete: true, Reasons: []string{}}, Keys: keys}}, Sudo: accountSudo{Complete: true, Grants: []grant{}, Reasons: []string{}}}
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
	a.KeyFiles = append(a.KeyFiles, keyFile{envelope: envelope{Path: "/home/alice/.ssh/authorized_keys2", Status: statusRead, Complete: true, Reasons: []string{}}, Keys: parseAuthorizedKeys([]byte(files[1].String()), &budget).keys})
	var trust strings.Builder
	for i := 0; i < maxTrustEntries; i++ {
		fmt.Fprintf(&trust, "p%0250d\n", i)
	}
	entries, _, _ := parseK5Login([]byte(trust.String()))
	a.TrustFiles = []trustFile{{envelope: envelope{Path: "/home/alice/.k5login", Status: statusRead, Complete: true, Reasons: []string{}}, Kind: "k5login", Entries: entries}}
	r := newTestReport()
	small := parseAuthorizedKeys([]byte("ssh-ed25519 "+testEd0+" ok\n"), newBudget()).keys
	r.Accounts = []account{a, capAccount("deploy", small), capAccount("root", small), capAccount("ubuntu", small)}
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
	a.TrustFiles = []trustFile{{envelope: envelope{Path: "/home/a/.k5login", Status: statusRead, Complete: true}, Entries: validTrustEntries(1200)}}
	for i := range a.TrustFiles[0].Entries {
		a.TrustFiles[0].Entries[i].Principal = ptr(strings.Repeat("a", 256))
	}
	r.Accounts = []account{a}
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
	r.Accounts = []account{a, capAccount("b", nil)}
	_, err := finalize(r)
	require.NoError(t, err)
	require.Len(t, r.Accounts, 1)
	assert.Equal(t, "b", r.Accounts[0].Username)
	assert.Contains(t, r.Categories[catAccounts].Reasons, reasonLimitExceeded)
}

func TestObservationRows(t *testing.T) {
	tests := []struct {
		name   string
		report exposureReport
		want   int
	}{
		{"empty", exposureReport{}, 0},
		{"accounts", exposureReport{Accounts: make([]account, 2)}, 2},
		{"authorization variants", exposureReport{Accounts: []account{{KeyFiles: []keyFile{{Keys: []key{
			{Authorizations: []authorization{{Count: 99}, {Count: 3}}},
			{Authorizations: []authorization{{Count: 7}}}, {},
		}}}}}}, 4},
		{"principals entries", exposureReport{Accounts: []account{{PrincipalsFiles: []principalsFile{{Entries: []principalEntry{{Principals: []string{"a", "b"}}, {}}}}}}}, 3},
		{"trust entries", exposureReport{Accounts: []account{{TrustFiles: []trustFile{{Entries: validTrustEntries(2)}}}}}, 3},
		{"system trust entries", exposureReport{SystemTrust: []systemTrustFile{{Entries: make([]hostUser, 2)}, {Entries: make([]hostUser, 3)}}}, 5},
		{"user-CA entries", exposureReport{UserCA: &userCA{CAs: make([]caKey, 2)}}, 2},
		{"sudo grants", exposureReport{Accounts: []account{{Sudo: accountSudo{Grants: make([]grant, 2)}}}}, 3},
		{"external records", exposureReport{External: make([]external, 2)}, 2},
		{"metadata", exposureReport{Accounts: []account{{Groups: []string{"a", "b"}, LastPTYLogin: &ptyLogin{}, KeyFiles: []keyFile{{}}, PrincipalsFiles: []principalsFile{{}}, TrustFiles: []trustFile{{}}}}, SSHD: sshdPolicy{MatchBlocks: []matchSettings{{}}}}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { assert.Equal(t, tt.want, observationRows(&tt.report)) })
	}
}

func rowCapReport(rows int) *exposureReport {
	r := newTestReport()
	for i := range 100 {
		a := capAccount(fmt.Sprintf("small%03d", i), nil)
		a.TrustFiles = []trustFile{{envelope: envelope{Path: "/home/" + a.Username + "/.k5login", Complete: true}, Entries: validTrustEntries(190)}}
		r.Accounts = append(r.Accounts, a)
	}
	keys := make([]key, rows-observationRows(r)-501)
	for i := range keys {
		keys[i].Authorizations = []authorization{{Count: 1}}
	}
	a := capAccount("huge", keys)
	a.Sudo.Grants = make([]grant, 500)
	r.Accounts = append(r.Accounts, a)
	return r
}

func TestObservationRowCapBoundary(t *testing.T) {
	for _, rows := range []int{maxObservationRows, maxObservationRows + 1} {
		t.Run(fmt.Sprint(rows), func(t *testing.T) {
			r := rowCapReport(rows)
			require.Equal(t, rows, observationRows(r))
			require.Greater(t, encodedLen(r.Accounts[100].KeyFiles[0]), encodedLen(r.Accounts[100].Sudo), "row count takes priority over source bytes")
			before, err := seal(r)
			require.NoError(t, err)
			require.Less(t, len(before), maxReportBytes)
			for _, a := range r.Accounts {
				require.Less(t, encodedLen(a), maxAccountBytes)
			}
			body, err := finalize(r)
			require.NoError(t, err)
			assert.Len(t, r.Accounts, 101)
			assert.LessOrEqual(t, observationRows(r), maxObservationRows)
			if rows == maxObservationRows {
				assert.Equal(t, before, body)
				return
			}
			a := r.Accounts[100]
			assert.Empty(t, a.Sudo.Grants)
			assert.False(t, a.Sudo.Complete)
			assert.Equal(t, []string{reasonLimitExceeded}, a.Sudo.Reasons)
			assert.Equal(t, coverage{Status: coveragePartial, Reasons: []string{reasonLimitExceeded}}, r.Categories[catSudo])
			assert.Equal(t, rows-500, observationRows(r), "stop after one source")
			assert.True(t, a.KeyFiles[0].Complete)
			assert.Empty(t, a.KeyFiles[0].Reasons)
			for _, a := range r.Accounts[:100] {
				assert.True(t, a.KeyFiles[0].Complete)
				assert.True(t, a.TrustFiles[0].Complete)
				assert.Len(t, a.TrustFiles[0].Entries, 190)
				assert.Empty(t, a.TrustFiles[0].Reasons)
				assert.True(t, a.Sudo.Complete)
			}
			again, err := seal(r)
			require.NoError(t, err)
			assert.Equal(t, body, again, "hash covers the cut report")
		})
	}
}

func TestObservationRowCapSourceOrder(t *testing.T) {
	for _, differentSize := range []bool{false, true} {
		t.Run(fmt.Sprintf("different size=%t", differentSize), func(t *testing.T) {
			r := rowCapReport(maxObservationRows + 1)
			a := &r.Accounts[100]
			// Equal-row sources use encoded size, then path order.
			a.KeyFiles = nil
			a.Sudo.Grants = nil
			a.TrustFiles = []trustFile{
				{envelope: envelope{Path: "/z", Complete: true}, Entries: validTrustEntries(450)},
				{envelope: envelope{Path: "/a", Complete: true}, Entries: validTrustEntries(450)},
			}
			want := 1
			if differentSize {
				a.TrustFiles[0].Entries[0].Principal = ptr("longer")
				want = 0
			}
			require.Equal(t, maxObservationRows+1, observationRows(r))
			_, err := finalize(r)
			require.NoError(t, err)
			assert.Empty(t, a.TrustFiles[want].Entries)
			assert.False(t, a.TrustFiles[want].Complete)
			assert.Equal(t, []string{reasonLimitExceeded}, a.TrustFiles[want].Reasons)
			assert.True(t, a.TrustFiles[1-want].Complete)
			assert.Len(t, a.TrustFiles[1-want].Entries, 450)
		})
	}
}

func TestEmptyAccountSourcesFitObservationRowCap(t *testing.T) {
	r := newTestReport()
	r.Accounts = make([]account, maxAccounts)
	// The six global provider kinds and three per-account Match providers.
	r.External = make([]external, 6+3*maxAccounts)
	r.UserCA = &userCA{CAs: make([]caKey, maxKeysPerAccount)}
	r.SystemTrust = []systemTrustFile{{Entries: make([]hostUser, maxTrustEntries)}, {Entries: make([]hostUser, maxTrustEntries)}}
	assert.Less(t, observationRows(r), maxObservationRows)
}

func TestObservationRowCapReselectsLargestAccount(t *testing.T) {
	r := rowCapReport(maxObservationRows + 1)
	a := capAccount("second", []key{{Authorizations: make([]authorization, 390)}})
	a.Sudo.Grants = make([]grant, 500)
	r.Accounts = append(r.Accounts, a)
	_, err := finalize(r)
	require.NoError(t, err)
	assert.LessOrEqual(t, observationRows(r), maxObservationRows)
	assert.Len(t, r.Accounts, 102)
	for _, a := range r.Accounts[100:] {
		assert.False(t, a.Sudo.Complete)
		assert.Empty(t, a.Sudo.Grants)
		assert.True(t, a.KeyFiles[0].Complete, "switch accounts after the first cut")
		assert.NotEmpty(t, a.KeyFiles[0].Keys)
	}
}

func TestRowCapNoAccountSources(t *testing.T) {
	r := &exposureReport{Categories: map[string]coverage{}}
	for i := 0; i <= maxObservationRows; i++ {
		r.External = append(r.External, external{Kind: externalKeysCommand, Scope: "match:" + strconv.Itoa(i)})
	}
	body, err := finalize(r)
	require.NoError(t, err)
	var decoded exposureReport
	require.NoError(t, json.Unmarshal(body, &decoded))
	// This synthetic input exceeds the collector's external-record cap and
	// has no account sources to cut. Do not claim any source was truncated.
	assert.Equal(t, maxObservationRows+1, observationRows(&decoded))
	assert.Empty(t, decoded.Accounts)
	assert.Empty(t, decoded.Categories)
}

func validTrustEntries(n int) []trustEntry {
	entries := make([]trustEntry, n)
	for i := range entries {
		entries[i].Principal = ptr("u")
	}
	return entries
}
