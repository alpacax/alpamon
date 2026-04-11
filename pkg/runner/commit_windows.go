package runner

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

func loadValidShells() []string {
	return []string{"powershell.exe", "cmd.exe"}
}

func loadShadowData() map[string]shadowEntry {
	return nil
}

// getUserData enumerates local users via "wmic useraccount" on Windows.
func getUserData() ([]UserData, error) {
	out, err := exec.Command("wmic", "useraccount", "get", "Name,SID", "/format:csv").Output()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to list users via wmic.")
		return nil, fmt.Errorf("wmic useraccount failed: %w", err)
	}

	validShells := loadValidShells()
	var users []UserData

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			continue
		}
		username := strings.TrimSpace(fields[1])
		sid := strings.TrimSpace(fields[2])
		if username == "" || sid == "" {
			continue
		}

		uid := ridFromSID(sid)

		homeDir := filepath.Join(`C:\Users`, username)
		users = append(users, UserData{
			Username:    username,
			UID:         uid,
			GID:         0,
			Directory:   homeDir,
			Shell:       utils.DefaultShell(),
			ValidShells: validShells,
		})
	}

	if users == nil {
		users = []UserData{}
	}
	return users, nil
}

// getGroupData enumerates local groups via "wmic group" on Windows.
func getGroupData() ([]GroupData, error) {
	out, err := exec.Command("wmic", "group", "get", "Name,SID", "/format:csv").Output()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to list groups via wmic.")
		return nil, fmt.Errorf("wmic group failed: %w", err)
	}

	var groups []GroupData
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			continue
		}
		groupName := strings.TrimSpace(fields[1])
		sid := strings.TrimSpace(fields[2])
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
