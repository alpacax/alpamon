package runner

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alpacax/alpamon/pkg/utils"
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
func parseGetLocalUserCSV(csv string) []UserData {
	validShells := loadValidShells()
	var users []UserData

	for _, line := range strings.Split(csv, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "\"Name\"") {
			continue
		}
		fields := parseCSVLine(line)
		if len(fields) < 3 {
			continue
		}
		username := fields[0]
		sid := fields[1]
		enabled := strings.EqualFold(fields[2], "True")
		if username == "" || sid == "" {
			continue
		}

		uid := ridFromSID(sid)

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
		if line == "" || strings.HasPrefix(line, "\"Name\"") {
			continue
		}
		fields := parseCSVLine(line)
		if len(fields) < 2 {
			continue
		}
		groupName := fields[0]
		sid := fields[1]
		if groupName == "" {
			continue
		}

		gid := ridFromSID(sid)

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

// parseCSVLine parses a simple CSV line with quoted fields.
// Handles: "value1","value2","value3"
func parseCSVLine(line string) []string {
	var fields []string
	for _, f := range strings.Split(line, ",") {
		f = strings.TrimSpace(f)
		f = strings.Trim(f, "\"")
		fields = append(fields, f)
	}
	return fields
}
