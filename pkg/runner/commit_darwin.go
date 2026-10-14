package runner

import (
	"fmt"
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

// getUserData enumerates local users via a single dscl -readall call on macOS.
// All user attributes are fetched via dscl to avoid os/user.Lookup(),
// which requires CGO on macOS and fails with CGO_ENABLED=0 builds.
func getUserData() ([]UserData, error) {
	out, err := exec.Command("dscl", ".", "-readall", "/Users",
		"RecordName", "UniqueID", "PrimaryGroupID", "NFSHomeDirectory", "UserShell").Output()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to read users via dscl, skipping the users sync.")
		return nil, err
	}

	return usersFromDscl(out)
}

// usersFromDscl warns on a parse failure because callers log collection errors at Debug only.
func usersFromDscl(out []byte) ([]UserData, error) {
	users, err := parseDsclUsers(string(out), loadValidShells())
	if err != nil {
		log.Warn().Err(err).Msg("Failed to parse dscl user records, skipping the users sync.")
		return nil, err
	}
	return users, nil
}

// parseDsclUsers parses `dscl . -readall /Users`: a "-" line ends a record, and dscl moves an
// attribute's values to indented lines when any holds a space, so inline values split on spaces.
func parseDsclUsers(out string, validShells []string) ([]UserData, error) {
	users := []UserData{}

	flush := func(rec map[string]string) {
		name := rec["RecordName"]
		uid, err := strconv.Atoi(rec["UniqueID"])
		if name == "" || err != nil {
			return
		}
		gid, err := strconv.Atoi(rec["PrimaryGroupID"])
		if err != nil {
			gid = 0
		}
		shell := rec["UserShell"]
		if shell == "" {
			shell = utils.DefaultShell()
		}
		users = append(users, UserData{
			Username:    name,
			UID:         uid,
			GID:         gid,
			Directory:   rec["NFSHomeDirectory"],
			Shell:       shell,
			ValidShells: validShells,
		})
	}

	rec := map[string]string{}
	pending := "" // attribute whose values follow on indented lines
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "-" {
			flush(rec)
			clear(rec)
			pending = ""
			continue
		}
		if strings.HasPrefix(line, " ") {
			if pending != "" {
				if _, ok := rec[pending]; !ok {
					rec[pending] = strings.TrimSpace(line)
				}
			}
			continue
		}
		attr, value, ok := strings.Cut(line, ":")
		pending = ""
		if !ok {
			continue
		}
		if _, exists := rec[attr]; exists { // a lost "-" separator would merge users into one record
			return nil, fmt.Errorf("dscl output repeats %s within one record", attr)
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			pending = attr
			continue
		}
		rec[attr] = fields[0]
	}
	flush(rec)

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
