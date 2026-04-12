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

// getUserData enumerates local users via PowerShell on Windows.
// Only Administrator (RID 500) gets a login shell because alpamon cannot
// demote privileges on Windows (no setuid equivalent). All sessions run
// as SYSTEM, so allowing non-admin users would be a privilege escalation.
// When credential-based demotion is implemented, other Enabled users can
// be granted login shells.
func getUserData() ([]UserData, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-LocalUser | Select-Object Name,SID,Enabled | ConvertTo-Csv -NoTypeInformation").Output()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to list users via PowerShell.")
		return []UserData{}, nil
	}

	validShells := loadValidShells()
	var users []UserData

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "\"Name\"") {
			continue
		}
		// CSV format: "Name","SID","Enabled"
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

		// Only grant login shell to Administrator (RID 500) since all
		// sessions run as SYSTEM without privilege demotion.
		shell := ""
		if enabled && uid == 500 {
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
	return users, nil
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
