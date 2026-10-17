package runner

import (
	"fmt"
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
	out, err := runCollectCommand("dscl", ".", "-readall", "/Users",
		"RecordName", "UniqueID", "PrimaryGroupID", "NFSHomeDirectory", "UserShell")
	if err != nil {
		log.Warn().Err(err).Msg("Failed to read users via dscl; users will not be reported.")
		return nil, err
	}

	return usersFromDscl(out)
}

// usersFromDscl warns on a parse failure because callers log collection errors at Debug only.
func usersFromDscl(out []byte) ([]UserData, error) {
	users, err := parseDsclUsers(string(out), loadValidShells())
	if err != nil {
		log.Warn().Err(err).Msg("Failed to parse dscl user records; users will not be reported.")
		return nil, err
	}
	return users, nil
}

// parseDsclUsers parses `dscl . -readall /Users`: a "-" line ends a record, and dscl moves an
// attribute's values to indented lines when any holds a space, so inline values split on spaces.
func parseDsclUsers(out string, validShells []string) ([]UserData, error) {
	users := []UserData{}

	rec := map[string]string{}
	pending := "" // attribute whose values follow on indented lines
	for line := range strings.SplitSeq(out, "\n") {
		if line == "-" {
			if u, ok := userFromRecord(rec, validShells); ok {
				users = append(users, u)
			}
			clear(rec)
			pending = ""
			continue
		}
		if strings.HasPrefix(line, " ") {
			if pending != "" && rec[pending] == "" {
				rec[pending] = strings.TrimSpace(line)
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
			rec[attr] = "" // marks the attribute as seen even if no indented value follows
			pending = attr
			continue
		}
		rec[attr] = fields[0]
	}
	if u, ok := userFromRecord(rec, validShells); ok {
		users = append(users, u)
	}

	return users, nil
}

// userFromRecord maps one dscl record; ok is false when it lacks a name or a numeric UniqueID.
func userFromRecord(rec map[string]string, validShells []string) (UserData, bool) {
	name := rec["RecordName"]
	uid, err := strconv.Atoi(rec["UniqueID"])
	if name == "" || err != nil {
		return UserData{}, false
	}
	gid, err := strconv.Atoi(rec["PrimaryGroupID"])
	if err != nil {
		gid = 0 // Atoi returns the max int on a range error
	}
	shell := rec["UserShell"]
	if shell == "" {
		shell = utils.DefaultShell()
	}
	return UserData{
		Username:    name,
		UID:         uid,
		GID:         gid,
		Directory:   rec["NFSHomeDirectory"],
		Shell:       shell,
		ValidShells: validShells,
	}, true
}

// getGroupData enumerates local groups via dscl on macOS.
func getGroupData() ([]GroupData, error) {
	out, err := runCollectCommand("dscl", ".", "-list", "/Groups", "PrimaryGroupID")
	if err != nil {
		log.Warn().Err(err).Msg("Failed to list groups via dscl; groups will not be reported.")
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
