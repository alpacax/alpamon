package exposure

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSudoAliasWhitespaceAndUndefined(t *testing.T) {
	s := sudoFor(t, "User_Alias\tADMINS = alice\nADMINS ALL=(ALL) ALL\n", "alice")
	assert.True(t, s.Complete)
	assert.Len(t, s.Grants, 1)
	s = sudoFor(t, "ADMINS ALL=(ALL) ALL\n", "alice")
	assert.False(t, s.Complete)
	assert.Contains(t, s.Reasons, reasonSudoUnsupportedSyntax)
}
func TestSudoCommentsNeverContinue(t *testing.T) {
	for _, prefix := range []string{"# note \\\n", "bob ALL=(ALL) ALL # x \\\n"} {
		s := sudoFor(t, prefix+"alice ALL=(ALL) ALL\n", "alice")
		assert.True(t, s.Complete)
		assert.Len(t, s.Grants, 1)
	}
	assert.Len(t, sudoFor(t, "bob ALL=(ALL) ALL # x \\\nalice ALL=(ALL) ALL\n", "bob").Grants, 1)
	toks, ok := tokenizeSudo("#123 ALL=(#0) ALL")
	require.True(t, ok)
	assert.Equal(t, "#123", toks[0].text)
}
func TestSudoArgsRestrictionIntersection(t *testing.T) {
	for _, commands := range []string{"/usr/bin/vim, /bin/systemctl restart nginx", "/bin/cat /var/log/*", "/bin/cat /var/log/?", "/bin/cat /var/log/[ab]"} {
		s := sudoFor(t, "alice ALL="+commands, "alice")
		require.Len(t, s.Grants, 1)
		assert.False(t, s.Grants[0].ArgsRestricted, commands)
	}
}
func TestSudoAliasRecursionPath(t *testing.T) {
	for _, policy := range []string{
		"User_Alias U = alice\nU, U ALL = ALL",
		"User_Alias X = alice\nUser_Alias B = X\nUser_Alias A = B, X\nA ALL = ALL",
		"User_Alias A = B, X\nUser_Alias B = X\nUser_Alias X = alice\nA ALL = ALL",
		"Host_Alias X = ALL\nHost_Alias B = X\nHost_Alias A = B, X\nalice A = ALL",
		"Runas_Alias X = root\nRunas_Alias B = X\nRunas_Alias A = B, X\nalice ALL = (A) ALL",
		"Cmnd_Alias X = /bin/cat\nCmnd_Alias B = X\nCmnd_Alias A = B, X\nalice ALL = A",
	} {
		s := sudoFor(t, policy, "alice")
		assert.True(t, s.Complete, policy)
		assert.NotContains(t, s.Reasons, reasonSudoUnsupportedSyntax)
		assert.NotEmpty(t, s.Grants)
	}
	s := sudoFor(t, "User_Alias A = B\nUser_Alias B = A\nA ALL = ALL", "alice")
	assert.False(t, s.Complete)
	assert.Contains(t, s.Reasons, reasonSudoUnsupportedSyntax)
}
func TestMatchFirstValueWins(t *testing.T) {
	cfg := parseSSHDConfig(mapSource{files: map[string]string{sshdConfigPath: "Match User alice\nPasswordAuthentication yes\nPasswordAuthentication no\nAuthorizedKeysCommand /bin/first\nAuthorizedKeysCommand /bin/second\nAuthorizedKeysCommandUser root\nAuthorizedKeysCommandUser nobody\n"}})
	require.Len(t, cfg.blocks, 1)
	b := cfg.blocks[0]
	assert.Equal(t, "yes", b.block.Sets["passwordauthentication"])
	require.NotNil(t, b.keysCommand)
	assert.Equal(t, "/bin/first", *b.keysCommand.path)
	assert.Equal(t, "root", *b.keysCommand.user)
}
func TestSSHDArgumentCommentsAndQuotes(t *testing.T) {
	kw, args, ok := splitConfigLine([]byte("PasswordAuthentication yes # note"))
	require.True(t, ok)
	assert.Equal(t, "passwordauthentication", kw)
	assert.Equal(t, []string{"yes"}, args)
	_, args, ok = splitConfigLine([]byte("Match User alice # note"))
	require.True(t, ok)
	assert.False(t, newMatchBlock(args).unsupported)
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"'one two'", []string{"one two"}},
		{`"one two"`, []string{"one two"}},
		{`one\ two a\"b c\\d x#y # end`, []string{"one two", `a"b`, `c\d`, "x#y"}},
	} {
		got, ok := splitArgs(tc.in)
		assert.True(t, ok)
		assert.Equal(t, tc.want, got)
	}
}
func TestCanonicalDoesNotMutateNestedSlices(t *testing.T) {
	r := exposureReport{UserCA: &userCA{}, Accounts: []account{{KeyFiles: []keyFile{{Keys: []key{{Authorizations: []authorization{{}}}}}}}}}
	_, err := encodeValue(r)
	require.NoError(t, err)
	assert.Nil(t, r.UserCA.CAs)
	assert.Nil(t, r.UserCA.Reasons)
	assert.Nil(t, r.Accounts[0].Groups)
	assert.Nil(t, r.Accounts[0].KeyFiles[0].Keys[0].Authorizations[0].Options)
}
func TestZeroTrustEntryRejected(t *testing.T) {
	_, err := json.Marshal(trustEntry{})
	require.Error(t, err)
}
