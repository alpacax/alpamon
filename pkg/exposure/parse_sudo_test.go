package exposure

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sudoFor(t *testing.T, sudoers string, user string, groups ...string) accountSudo {
	t.Helper()
	pol := readSudoPolicy(mapSource{files: map[string]string{sudoersPath: sudoers}}, "web-1.example.com")
	member := map[string]bool{}
	for _, g := range groups {
		member[g] = true
	}
	return pol.forAccount(user, func(g string) bool { return member[g] })
}

func TestSudoSupportedGrammar(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sudoers string
		user    string
		groups  []string
		want    []grant
	}{
		{"user ALL", "alice ALL=(ALL:ALL) ALL\n", "alice", nil,
			[]grant{{Source: sudoersPath, Via: "user:alice", Runas: "ALL:ALL", Commands: "all", CommandPaths: []string{}}}},
		{"group NOPASSWD", "%wheel ALL=(ALL) NOPASSWD: ALL\n", "bob", []string{"wheel"},
			[]grant{{Source: sudoersPath, Via: "group:wheel", Runas: "ALL", Commands: "all", CommandPaths: []string{}, NoPasswd: true}}},
		{"default runas", "alice ALL = /usr/bin/id\n", "alice", nil,
			[]grant{{Source: sudoersPath, Via: "user:alice", Runas: "root", Commands: "limited", CommandPaths: []string{"/usr/bin/id"}}}},
		{"own short hostname", "alice web-1 = (root) /usr/bin/id --verbose\n", "alice", nil,
			[]grant{{Source: sudoersPath, Via: "user:alice", Runas: "root", Commands: "limited", CommandPaths: []string{"/usr/bin/id"}, ArgsRestricted: true}}},
		{"tags carry and split", "alice ALL = (root) NOPASSWD: /bin/a, /bin/b, PASSWD: /bin/c\n", "alice", nil,
			[]grant{
				{Source: sudoersPath, Via: "user:alice", Runas: "root", Commands: "limited", CommandPaths: []string{"/bin/a", "/bin/b"}, NoPasswd: true},
				{Source: sudoersPath, Via: "user:alice", Runas: "root", Commands: "limited", CommandPaths: []string{"/bin/c"}},
			}},
		{"aliases", "User_Alias ADMINS = alice, %ops\nRunas_Alias DB = postgres\nHost_Alias HERE = web-1\nCmnd_Alias PSQL = /usr/bin/psql\nADMINS HERE = (DB) PSQL\n", "carol", []string{"ops"},
			[]grant{{Source: sudoersPath, Via: "group:ops", Runas: "postgres", Commands: "limited", CommandPaths: []string{"/usr/bin/psql"}}}},
		{"alias used before its definition", "ADMINS ALL = ALL\nUser_Alias ADMINS = alice\n", "alice", nil,
			[]grant{{Source: sudoersPath, Via: "user:alice", Runas: "root", Commands: "all", CommandPaths: []string{}}}},
		{"second host group", "alice ALL = /bin/a : web-1 = (postgres) /usr/bin/id\n", "alice", nil,
			[]grant{
				{Source: sudoersPath, Via: "user:alice", Runas: "root", Commands: "limited", CommandPaths: []string{"/bin/a"}},
				{Source: sudoersPath, Via: "user:alice", Runas: "postgres", Commands: "limited", CommandPaths: []string{"/usr/bin/id"}},
			}},
		{"empty args", `alice ALL = /usr/bin/ls ""` + "\n", "alice", nil,
			[]grant{{Source: sudoersPath, Via: "user:alice", Runas: "root", Commands: "limited", CommandPaths: []string{"/usr/bin/ls"}, ArgsRestricted: true}}},
		{"continuation line", "alice ALL = /bin/a, \\\n  /bin/b\n", "alice", nil,
			[]grant{{Source: sudoersPath, Via: "user:alice", Runas: "root", Commands: "limited", CommandPaths: []string{"/bin/a", "/bin/b"}}}},
		{"comment and other users", "# alice ALL = ALL\nbob ALL = ALL # trailing\n", "alice", nil, []grant{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sudoFor(t, tc.sudoers, tc.user, tc.groups...)
			assert.True(t, got.Complete, "%v", got.Reasons)
			assert.Empty(t, got.Reasons)
			assert.Equal(t, tc.want, got.Grants)
		})
	}
}

func TestSudoIncompleteRules(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sudoers string
		reason  string
		// other is an account the rule does not name; allAccounts means it
		// is affected too.
		allAccounts bool
	}{
		{"negated command", "alice ALL = ALL, !/usr/bin/su LEAKCANARY\n", reasonSudoUnsupportedSyntax, false},
		{"digest", "alice ALL = sha256:LEAKCANARY /usr/bin/x\n", reasonSudoUnsupportedSyntax, false},
		{"Cmnd_Alias exclusion", "Cmnd_Alias C = /bin/a, !/bin/b\nalice ALL = C\n", reasonSudoUnsupportedSyntax, false},
		{"glob command", "alice ALL = /usr/bin/*\n", reasonSudoUnsupportedSyntax, false},
		{"directory command", "alice ALL = /usr/bin/\n", reasonSudoUnsupportedSyntax, false},
		{"sudoedit", "alice ALL = sudoedit /etc/hosts\n", reasonSudoUnsupportedSyntax, false},
		{"command option", "alice ALL = (root) CWD=/tmp /bin/a\n", reasonSudoUnsupportedSyntax, false},
		{"netgroup host", "alice +hosts = ALL\n", reasonSudoUnsupportedSyntax, false},
		{"negated host", "alice ALL, !web-1 = ALL\n", reasonSudoUnsupportedSyntax, false},
		{"uid runas", "alice ALL = (#0) ALL\n", reasonSudoUnsupportedSyntax, false},
		{"undefined runas alias", "alice ALL = (DBA) ALL\n", reasonSudoUnsupportedSyntax, false},
		{"other host", "alice db-1 = ALL\n", reasonSudoHostConditional, false},
		{"address host", "alice 10.0.0.1 = ALL\n", reasonSudoHostConditional, false},
		{"Defaults for one user", "Defaults:alice !authenticate\n", reasonSudoUnsupportedSyntax, false},
		{"global auth Defaults", "Defaults targetpw\n", reasonSudoUnsupportedSyntax, true},
		{"command-bound Defaults", "Defaults!/bin/a rootpw\n", reasonSudoUnsupportedSyntax, true},
		{"negated user", "!alice ALL = ALL\n", reasonSudoUnsupportedSyntax, true},
		{"uid user", "#1001 ALL = ALL\n", reasonSudoUnsupportedSyntax, true},
		{"non-unix group", "%:admins ALL = ALL\n", reasonSudoUnsupportedSyntax, true},
		{"unsupported User_Alias", "User_Alias A = alice, !bob\n", reasonSudoUnsupportedSyntax, true},
		{"unterminated quote", "alice ALL = /bin/a \"x\n", reasonParseError, true},
		{"include with a host token", "@include /etc/sudoers.%h\n", reasonParseError, true},
		{"missing include", "@include /etc/sudoers.local\n", reasonFileUnreadable, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sudoFor(t, tc.sudoers, "alice")
			assert.False(t, got.Complete)
			assert.Contains(t, got.Reasons, tc.reason)
			out, err := encodeValue(got)
			require.NoError(t, err)
			assert.NotContains(t, string(out), "LEAKCANARY")
			other := sudoFor(t, tc.sudoers, "zed")
			assert.Equal(t, tc.allAccounts, !other.Complete, "unaffected account: %v", other.Reasons)
		})
	}
}

func TestSudoIncludes(t *testing.T) {
	src := mapSource{
		files: map[string]string{
			sudoersPath:             "@includedir /etc/sudoers.d\n#include local\n",
			"/etc/local":            "alice ALL = /bin/local\n",
			"/etc/sudoers.d/10-a":   "alice ALL = /bin/a\n",
			"/etc/sudoers.d/a.conf": "alice ALL = /bin/dot\n",
			"/etc/sudoers.d/b~":     "alice ALL = /bin/tilde\n",
		},
		dirs: map[string][]string{"/etc/sudoers.d": {"b~", "a.conf", "10-a"}},
	}
	pol := readSudoPolicy(src, "h")
	got := pol.forAccount("alice", func(string) bool { return false })
	assert.True(t, got.Complete)
	require.Len(t, got.Grants, 2)
	assert.Equal(t, "/etc/sudoers.d/10-a", got.Grants[0].Source)
	assert.Equal(t, "/etc/local", got.Grants[1].Source, "a relative include is taken from the including file's directory")

	files := map[string]string{sudoersPath: "@include /etc/s0\n"}
	for i := range maxIncludeFiles + 2 {
		files[fmt.Sprintf("/etc/s%d", i)] = fmt.Sprintf("@include /etc/s%d\n", i+1)
	}
	pol = readSudoPolicy(mapSource{files: files}, "h")
	assert.True(t, pol.global.has(reasonLimitExceeded))
}

func TestSudoIncludeHashInPath(t *testing.T) {
	for _, directive := range []string{"#include", "@include", "#includedir", "@includedir"} {
		t.Run(directive, func(t *testing.T) {
			path := "/etc/sudoers.d/a#b"
			line := directive + " " + path
			got, quotedComment := stripSudoComment(line)
			assert.Equal(t, line, got)
			assert.False(t, quotedComment)
			src := mapSource{files: map[string]string{sudoersPath: line + "\n"}}
			if strings.HasSuffix(directive, "dir") {
				src.dirs = map[string][]string{path: {"rule"}}
				path += "/rule"
			}
			src.files[path] = "alice ALL = /bin/id\n"
			pol := readSudoPolicy(src, "h")
			policy := pol.forAccount("alice", func(string) bool { return false })
			assert.True(t, policy.Complete)
			require.Len(t, policy.Grants, 1)
			assert.Equal(t, path, policy.Grants[0].Source)
			assert.Equal(t, []string{"/bin/id"}, policy.Grants[0].CommandPaths)
		})
	}
}

func TestSudoPolicySource(t *testing.T) {
	for _, tc := range []struct {
		name       string
		files      map[string]string
		unresolved bool
	}{
		{"no sudo.conf", map[string]string{sudoersPath: "alice ALL = ALL\n"}, false},
		{"sudoers plugin with a file", map[string]string{sudoConfPath: "Plugin sudoers_policy sudoers.so sudoers_file=/etc/alt\n", "/etc/alt": "alice ALL = ALL\n"}, false},
		{"another policy plugin", map[string]string{sudoConfPath: "Plugin approval_policy approval.so\n"}, true},
		{"sudo-rs policy file", map[string]string{sudoersPath: "alice ALL = ALL\n", sudoersRSPath: "alice ALL = ALL\n"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pol := readSudoPolicy(mapSource{files: tc.files}, "h")
			assert.Equal(t, tc.unresolved, pol.unresolved)
			got := pol.forAccount("alice", func(string) bool { return false })
			if tc.unresolved {
				assert.Equal(t, accountSudo{Reasons: []string{reasonSudoPolicyUnresolved}, Grants: []grant{}}, got)
			} else {
				assert.True(t, got.Complete)
				assert.Len(t, got.Grants, 1)
			}
		})
	}
	pol := readSudoPolicy(mapSource{status: map[string]string{sudoersPath: statusUnreadable}}, "h")
	got := pol.forAccount("alice", func(string) bool { return false })
	assert.False(t, got.Complete, "an unreadable policy is not no rights")
	assert.Contains(t, got.Reasons, reasonFileUnreadable)
}

func TestSudoCommandPathCap(t *testing.T) {
	var paths []string
	for i := range maxCommandPaths + 3 {
		paths = append(paths, fmt.Sprintf("/bin/c%d", i))
	}
	got := sudoFor(t, "alice ALL = "+strings.Join(paths, ", ")+"\n", "alice")
	assert.Contains(t, got.Reasons, reasonLimitExceeded)
	require.Len(t, got.Grants, 1)
	assert.Len(t, got.Grants[0].CommandPaths, maxCommandPaths)
}

func TestSudoAllUsers(t *testing.T) {
	p := readSudoPolicy(mapSource{files: map[string]string{sudoersPath: "ALL ALL=(ALL) NOPASSWD: ALL\n"}}, "host")
	for _, name := range []string{"alice", "bob", "root"} {
		s := p.forAccount(name, func(string) bool { return false })
		require.Len(t, s.Grants, 1)
		assert.True(t, s.Complete)
		assert.Empty(t, s.Reasons)
		assert.Equal(t, "all", s.Grants[0].Via)
		assert.Equal(t, "all", s.Grants[0].Commands)
		assert.True(t, s.Grants[0].NoPasswd)
	}
}

func TestSudoQuotedCommandArgumentsFailClosed(t *testing.T) {
	for _, policy := range []string{
		"alice ALL = /usr/bin/printf \" # \\\nbob ALL=(ALL) NOPASSWD: ALL, /bin/echo \"\n",
		"alice ALL = /bin/echo \" # \\\nbob ALL=(ALL) ALL\n",
		`alice ALL = /bin/echo "hello world"`,
		`alice ALL = /bin/echo a"b"c`,
		`alice ALL = /bin/echo a\"b`,
	} {
		t.Run(policy, func(t *testing.T) {
			for _, user := range []string{"alice", "bob", "carol"} {
				s := sudoFor(t, policy, user)
				assert.False(t, s.Complete, user)
				assert.Contains(t, s.Reasons, reasonSudoUnsupportedSyntax, user)
			}
		})
	}
}

func TestSudoRedefinedAliasesKeepFirstDefinition(t *testing.T) {
	for _, tc := range []struct {
		name, policy, user, runas, command string
	}{
		{"user", "User_Alias ADMINS = carol\nUser_Alias ADMINS = alice\nADMINS ALL=(ALL) ALL\n", "carol", "ALL", ""},
		{"host", "Host_Alias HERE = ALL\nHost_Alias HERE = elsewhere\ncarol HERE=(ALL) ALL\n", "carol", "ALL", ""},
		{"runas", "Runas_Alias RUN = root\nRunas_Alias RUN = nobody\ncarol ALL=(RUN) ALL\n", "carol", "root", ""},
		{"command", "Cmnd_Alias CMD = /bin/first\nCmnd_Alias CMD = /bin/second\ncarol ALL=(ALL) CMD\n", "carol", "ALL", "/bin/first"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := sudoFor(t, tc.policy, tc.user)
			assert.False(t, s.Complete)
			assert.Contains(t, s.Reasons, reasonSudoUnsupportedSyntax)
			require.Len(t, s.Grants, 1)
			assert.Equal(t, tc.runas, s.Grants[0].Runas)
			if tc.command != "" {
				assert.Equal(t, []string{tc.command}, s.Grants[0].CommandPaths)
			}
			other := sudoFor(t, tc.policy, "alice")
			assert.False(t, other.Complete)
			assert.Contains(t, other.Reasons, reasonSudoUnsupportedSyntax)
			assert.Empty(t, other.Grants)
		})
	}
}

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
