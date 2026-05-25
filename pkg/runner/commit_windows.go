package runner

import (
	"encoding/csv"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

func loadValidShells() []string {
	return []string{"powershell.exe", "cmd.exe", "pwsh.exe"}
}

func loadShadowData() map[string]shadowEntry {
	return nil
}

// getUserData enumerates local users via PowerShell on Windows and grants
// a login shell to Administrator (RID 500) plus every other enabled local
// user. All Websh sessions execute as LocalSystem because privilege
// demotion is not implemented on Windows; see parseGetLocalUserCSV for the
// trade-off and the Alpacon-RBAC dependency that justifies it.
func getUserData() ([]UserData, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-LocalUser | Select-Object Name,SID,Enabled | ConvertTo-Csv -NoTypeInformation").Output()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to list users via PowerShell.")
		return []UserData{}, nil
	}
	return parseGetLocalUserCSV(string(out)), nil
}

// parseGetLocalUserCSV parses the CSV output of
//
//	Get-LocalUser | Select-Object Name,SID,Enabled | ConvertTo-Csv -NoTypeInformation
//
// into UserData entries. A login shell is granted to:
//   - Administrator (RID 500) regardless of Enabled, because the built-in
//     admin is disabled by default on Windows 10/11 laptops; and
//   - every other locally-enabled user, on the same basis as Linux's
//     /etc/passwd-driven shell assignment.
//
// All Websh sessions on Windows execute as LocalSystem because
// pkg/utils/privilege_windows.go is currently a no-op stub. The session's
// displayed user is an audit label, not an OS-level permission boundary:
// Alpacon RBAC is the authorization surface, and operators must configure
// roles to reflect that granting Websh access on Windows grants SYSTEM
// execution.
func parseGetLocalUserCSV(csvData string) []UserData {
	validShells := loadValidShells()
	var users []UserData

	for _, line := range strings.Split(csvData, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := parseCSVLine(line)
		if len(fields) < 3 {
			continue
		}
		// Skip the header row produced by ConvertTo-Csv. Use exact
		// column-name match rather than a prefix check on the raw line
		// so a legitimate local user literally named "Name" is not
		// silently dropped.
		if fields[0] == "Name" && fields[1] == "SID" && fields[2] == "Enabled" {
			continue
		}
		username := fields[0]
		sid := fields[1]
		enabled := strings.EqualFold(fields[2], "True")
		if username == "" || sid == "" {
			continue
		}

		uid := ridFromSID(sid)
		if uid == 0 {
			// Local SAM RIDs start at 500; a parsed 0 means the SID did
			// not match the expected S-...-<rid> shape. Drop the row so
			// the widened enabled-user predicate cannot emit a malformed
			// UID=0 record with a login shell.
			continue
		}

		shell := ""
		if enabled || uid == 500 {
			shell = utils.DefaultShell()
		}

		users = append(users, UserData{
			Username:    username,
			UID:         uid,
			GID:         0,
			Directory:   filepath.Join(`C:\Users`, username),
			Shell:       shell,
			ValidShells: validShells,
		})
	}

	if users == nil {
		users = []UserData{}
	}
	return users
}

// getGroupData enumerates local groups via PowerShell on Windows.
func getGroupData() ([]GroupData, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-LocalGroup | Select-Object Name,SID | ConvertTo-Csv -NoTypeInformation").Output()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to list groups via PowerShell.")
		return []GroupData{}, nil
	}

	var groups []GroupData
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := parseCSVLine(line)
		if len(fields) < 2 {
			continue
		}
		// Skip the header row by exact column-name match; see the same
		// rationale on parseGetLocalUserCSV.
		if fields[0] == "Name" && fields[1] == "SID" {
			continue
		}
		groupName := fields[0]
		sid := fields[1]
		if groupName == "" {
			continue
		}

		gid := ridFromSID(sid)
		if gid == 0 {
			continue
		}

		groups = append(groups, GroupData{
			GID:       gid,
			GroupName: groupName,
		})
	}

	if groups == nil {
		groups = []GroupData{}
	}
	return groups, nil
}

// ridFromSID extracts the last component (RID) from a Windows SID string.
// e.g., "S-1-5-21-...-500" → 500. Returns 0 if parsing fails.
func ridFromSID(sid string) int {
	parts := strings.Split(sid, "-")
	if len(parts) < 2 {
		return 0
	}
	rid, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return 0
	}
	return rid
}

// parseCSVLine parses one RFC 4180 CSV record from a single line.
// Returns nil if the line is not well-formed CSV. Used for the output of
// PowerShell `ConvertTo-Csv -NoTypeInformation`, which emits RFC 4180.
func parseCSVLine(line string) []string {
	r := csv.NewReader(strings.NewReader(line))
	fields, err := r.Read()
	if err != nil {
		return nil
	}
	return fields
}
