package runner

import (
	"os/exec"
	"strconv"
	"strings"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

// loadValidShells returns the host's valid login shells from /etc/shells,
// falling back to the common macOS defaults when the list is empty or unavailable.
func loadValidShells() []string {
	shells := utils.LoadValidShells()
	if len(shells) == 0 {
		return []string{"/bin/bash", "/bin/zsh", "/bin/sh"}
	}
	return shells
}

// loadShadowData returns nil on macOS as there is no /etc/shadow.
func loadShadowData() map[string]shadowEntry {
	return nil
}

// getUserData enumerates local users via dscl on macOS.
// All user attributes are fetched via dscl to avoid os/user.Lookup(),
// which requires CGO on macOS and fails with CGO_ENABLED=0 builds.
func getUserData() ([]UserData, error) {
	out, err := exec.Command("dscl", ".", "-list", "/Users", "UniqueID").Output()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to list users via dscl.")
		return nil, err
	}

	validShells := loadValidShells()
	var users []UserData

	for line := range strings.SplitSeq(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		username := fields[0]
		uid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}

		gid := lookupDsclInt(username, "PrimaryGroupID")
		homeDir := lookupDsclAttr(username, "NFSHomeDirectory")
		shell := lookupDsclAttr(username, "UserShell")
		if shell == "" {
			shell = utils.DefaultShell()
		}

		users = append(users, UserData{
			Username:    username,
			UID:         uid,
			GID:         gid,
			Directory:   homeDir,
			Shell:       shell,
			ValidShells: validShells,
		})
	}

	if users == nil {
		users = []UserData{}
	}
	return users, nil
}

// getGroupData enumerates local groups via dscl on macOS.
func getGroupData() ([]GroupData, error) {
	out, err := exec.Command("dscl", ".", "-list", "/Groups", "PrimaryGroupID").Output()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to list groups via dscl.")
		return nil, err
	}

	var groups []GroupData
	for line := range strings.SplitSeq(string(out), "\n") {
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

// lookupDsclAttr reads a single attribute for a user via dscl.
// Returns empty string on failure.
func lookupDsclAttr(username, attr string) string {
	out, err := exec.Command("dscl", ".", "-read", "/Users/"+username, attr).Output()
	if err != nil {
		return ""
	}
	// Output format: "AttrName: value"
	parts := strings.SplitN(strings.TrimSpace(string(out)), " ", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

// lookupDsclInt reads a single integer attribute for a user via dscl.
// Returns 0 on failure.
func lookupDsclInt(username, attr string) int {
	s := lookupDsclAttr(username, attr)
	if s == "" {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}
