package runner

import (
	"bufio"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

// loadValidShells reads /etc/shells on macOS (which exists and follows the same format as Linux).
func loadValidShells() []string {
	const shellsFilePath = "/etc/shells"
	var shells []string

	file, err := os.Open(shellsFilePath)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to open /etc/shells, using defaults")
		return []string{"/bin/bash", "/bin/zsh", "/bin/sh"}
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		shells = append(shells, line)
	}

	if err := scanner.Err(); err != nil {
		log.Debug().Err(err).Msg("Error reading /etc/shells")
		return []string{"/bin/bash", "/bin/zsh", "/bin/sh"}
	}

	return shells
}

// loadShadowData returns nil on macOS as there is no /etc/shadow.
func loadShadowData() map[string]shadowEntry {
	return nil
}

// getUserData enumerates local users via dscl on macOS.
func getUserData() ([]UserData, error) {
	out, err := exec.Command("dscl", ".", "-list", "/Users", "UniqueID").Output()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to list users via dscl.")
		return nil, err
	}

	validShells := loadValidShells()
	var users []UserData

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		username := fields[0]
		uid, err := strconv.Atoi(fields[1])
		if err != nil || uid < 500 {
			continue // skip system users
		}

		usr, err := user.Lookup(username)
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(usr.Gid)
		if err != nil {
			log.Debug().Err(err).Str("username", username).Str("gid", usr.Gid).Msg("Failed to parse user GID.")
			continue
		}

		users = append(users, UserData{
			Username:    username,
			UID:         uid,
			GID:         gid,
			Directory:   usr.HomeDir,
			Shell:       lookupUserShell(username),
			ValidShells: validShells,
		})
	}

	if users == nil {
		users = []UserData{}
	}
	return users, nil
}

// lookupUserShell queries the user's login shell via dscl.
func lookupUserShell(username string) string {
	out, err := exec.Command("dscl", ".", "-read", "/Users/"+username, "UserShell").Output()
	if err != nil {
		return utils.DefaultShell()
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), " ", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return utils.DefaultShell()
}

// getGroupData enumerates local groups via dscl on macOS.
func getGroupData() ([]GroupData, error) {
	out, err := exec.Command("dscl", ".", "-list", "/Groups", "PrimaryGroupID").Output()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to list groups via dscl.")
		return nil, err
	}

	var groups []GroupData
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		gid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		groups = append(groups, GroupData{
			GID:       gid,
			GroupName: fields[0],
		})
	}

	if groups == nil {
		groups = []GroupData{}
	}
	return groups, nil
}
