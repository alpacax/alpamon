package runner

import (
	"os/exec"
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
		log.Debug().Err(err).Msg("Failed to list users via wmic.")
		return []UserData{}, nil
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
		if username == "" {
			continue
		}

		users = append(users, UserData{
			Username:    username,
			UID:         0,
			GID:         0,
			Directory:   `C:\Users\` + username,
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
		log.Debug().Err(err).Msg("Failed to list groups via wmic.")
		return []GroupData{}, nil
	}

	var groups []GroupData
	gid := 0
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}
		groupName := strings.TrimSpace(fields[1])
		if groupName == "" {
			continue
		}
		groups = append(groups, GroupData{
			GID:       gid,
			GroupName: groupName,
		})
		gid++
	}

	if groups == nil {
		groups = []GroupData{}
	}
	return groups, nil
}
