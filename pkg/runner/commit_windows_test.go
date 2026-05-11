package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseGetLocalUserCSV exercises the predicate that decides whether a
// local user receives a login shell. Administrator (RID 500) is always
// granted a shell (issue #302: built-in admin is disabled by default on
// Windows 10/11 laptops). Every other enabled user is also granted a
// shell, with all sessions running as LocalSystem until privilege demotion
// ships. Disabled non-admin users get no shell. The remaining cases guard
// the parser against header lines, malformed rows, and empty fields.
func TestParseGetLocalUserCSV(t *testing.T) {
	const header = "\"Name\",\"SID\",\"Enabled\"\n"
	const powershell = "powershell.exe"
	validShells := []string{"powershell.exe", "cmd.exe", "pwsh.exe"}

	cases := []struct {
		name string
		csv  string
		want []UserData
	}{
		{
			name: "Case A: Administrator enabled (AWS EC2) gets a login shell",
			csv:  header + "\"Administrator\",\"S-1-5-21-1-2-3-500\",\"True\"\n",
			want: []UserData{
				{
					Username:    "Administrator",
					UID:         500,
					GID:         0,
					Directory:   `C:\Users\Administrator`,
					Shell:       powershell,
					ValidShells: validShells,
				},
			},
		},
		{
			name: "Case B: Administrator disabled (Windows laptop default) still gets a login shell",
			csv:  header + "\"Administrator\",\"S-1-5-21-1-2-3-500\",\"False\"\n",
			want: []UserData{
				{
					Username:    "Administrator",
					UID:         500,
					GID:         0,
					Directory:   `C:\Users\Administrator`,
					Shell:       powershell,
					ValidShells: validShells,
				},
			},
		},
		{
			name: "Case C: non-Administrator enabled user receives a login shell",
			csv:  header + "\"alice\",\"S-1-5-21-1-2-3-1001\",\"True\"\n",
			want: []UserData{
				{
					Username:    "alice",
					UID:         1001,
					GID:         0,
					Directory:   `C:\Users\alice`,
					Shell:       powershell,
					ValidShells: validShells,
				},
			},
		},
		{
			name: "Case D: non-Administrator disabled user receives no login shell (regression guard)",
			csv:  header + "\"bob\",\"S-1-5-21-1-2-3-1002\",\"False\"\n",
			want: []UserData{
				{
					Username:    "bob",
					UID:         1002,
					GID:         0,
					Directory:   `C:\Users\bob`,
					Shell:       "",
					ValidShells: validShells,
				},
			},
		},
		{
			name: "mixed roster: disabled Administrator + disabled service accounts + enabled non-admin",
			csv: header +
				"\"Administrator\",\"S-1-5-21-1-2-3-500\",\"False\"\n" +
				"\"DefaultAccount\",\"S-1-5-21-1-2-3-503\",\"False\"\n" +
				"\"Guest\",\"S-1-5-21-1-2-3-501\",\"False\"\n" +
				"\"alice\",\"S-1-5-21-1-2-3-1001\",\"True\"\n",
			want: []UserData{
				{
					Username:    "Administrator",
					UID:         500,
					GID:         0,
					Directory:   `C:\Users\Administrator`,
					Shell:       powershell,
					ValidShells: validShells,
				},
				{
					Username:    "DefaultAccount",
					UID:         503,
					GID:         0,
					Directory:   `C:\Users\DefaultAccount`,
					Shell:       "",
					ValidShells: validShells,
				},
				{
					Username:    "Guest",
					UID:         501,
					GID:         0,
					Directory:   `C:\Users\Guest`,
					Shell:       "",
					ValidShells: validShells,
				},
				{
					Username:    "alice",
					UID:         1001,
					GID:         0,
					Directory:   `C:\Users\alice`,
					Shell:       powershell,
					ValidShells: validShells,
				},
			},
		},
		{
			name: "empty CSV returns an empty slice (not nil) so JSON marshals as []",
			csv:  "",
			want: []UserData{},
		},
		{
			name: "header-only input returns an empty slice",
			csv:  header,
			want: []UserData{},
		},
		{
			name: "row with fewer than three fields is skipped",
			csv:  header + "\"BrokenRow\",\"S-1-5-21-1-2-3-1002\"\n",
			want: []UserData{},
		},
		{
			name: "rows with empty username or empty SID are skipped",
			csv: header +
				"\"\",\"S-1-5-21-1-2-3-1003\",\"True\"\n" +
				"\"noid\",\"\",\"True\"\n",
			want: []UserData{},
		},
		{
			name: "row with a malformed SID (non-numeric RID) is skipped, not emitted as UID 0",
			csv:  header + "\"alice\",\"S-1-5-21-1-2-3-NOTANUMBER\",\"True\"\n",
			want: []UserData{},
		},
		{
			name: "row with a CSV-quoted value containing a comma round-trips correctly",
			csv:  header + "\"odd,name\",\"S-1-5-21-1-2-3-1500\",\"True\"\n",
			want: []UserData{
				{
					Username:    "odd,name",
					UID:         1500,
					GID:         0,
					Directory:   `C:\Users\odd,name`,
					Shell:       powershell,
					ValidShells: validShells,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseGetLocalUserCSV(tc.csv)
			assert.Equal(t, tc.want, got)
		})
	}
}
