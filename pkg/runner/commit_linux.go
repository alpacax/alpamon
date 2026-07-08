package runner

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

const (
	passwdFilePath = "/etc/passwd"
	groupFilePath  = "/etc/group"
	shadowFilePath = "/etc/shadow"
)

// loadValidShells returns the host's valid login shells from /etc/shells.
func loadValidShells() []string {
	return utils.LoadValidShells()
}

// loadShadowData reads /etc/shadow and returns expiration info by username
func loadShadowData() map[string]shadowEntry {
	entries := make(map[string]shadowEntry)

	file, err := os.Open(shadowFilePath)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to open /etc/shadow, skipping expiration checks")
		return nil
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}

		username := fields[0]

		entry := shadowEntry{
			username: username,
		}

		// Get raw expire date (8th field, index 7)
		if len(fields) >= 8 && fields[7] != "" {
			if expireDate, err := strconv.ParseInt(fields[7], 10, 64); err == nil {
				entry.expireDate = &expireDate
			}
		}

		entries[username] = entry
	}

	if err := scanner.Err(); err != nil {
		log.Debug().Err(err).Msg("Error reading /etc/shadow")
		return nil
	}

	return entries
}

func getUserData() ([]UserData, error) {
	users := []UserData{}

	// Load validation data once for all users
	validShells := loadValidShells() // []string - /etc/shells list
	shadowData := loadShadowData()

	file, err := os.Open(passwdFilePath)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to open passwd file.")
		return users, err
	}

	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			continue
		}

		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			continue
		}

		username := fields[0]

		// Collect raw data for server-side login_enabled determination
		var shadowExpireDate *int64

		// /etc/shadow data
		if shadowData != nil {
			if entry, exists := shadowData[username]; exists {
				shadowExpireDate = entry.expireDate // raw days since epoch
			}
		}

		users = append(users, UserData{
			Username:         username,
			UID:              uid,
			GID:              gid,
			Directory:        fields[5],
			Shell:            fields[6],
			ShadowExpireDate: shadowExpireDate,
			ValidShells:      validShells, // same list for all users
		})
	}

	err = scanner.Err()
	if err != nil {
		return users, err
	}

	return users, nil
}

func getGroupData() ([]GroupData, error) {
	groups := []GroupData{}

	file, err := os.Open(groupFilePath)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to open group file.")
		return groups, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) != 4 {
			continue
		}

		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}

		groups = append(groups, GroupData{
			GID:       gid,
			GroupName: fields[0],
		})
	}

	err = scanner.Err()
	if err != nil {
		return groups, err
	}

	return groups, nil
}
