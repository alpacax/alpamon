package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

func demote(username, groupname string) (*syscall.SysProcAttr, error) {
	currentUid := os.Getuid()

	if username == "" || groupname == "" {
		log.Debug().Msg("No username or groupname provided, running as the current user.")
		return nil, nil
	}

	if currentUid != 0 {
		log.Warn().Msg("Alpamon is not running as root. Falling back to the current user.")
		return nil, nil
	}

	usr, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("there is no corresponding %s username in this server", username)
	}

	group, err := user.LookupGroup(groupname)
	if err != nil {
		return nil, fmt.Errorf("there is no corresponding %s groupname in this server", groupname)
	}

	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return nil, err
	}

	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return nil, err
	}

	log.Debug().Msgf("Demote permission to match user: %s, group: %s.", username, groupname)

	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}, nil
}

func demoteFtp(username, groupname string) (*syscall.SysProcAttr, error) {
	currentUid := os.Getuid()

	if username == "" || groupname == "" {
		log.Debug().Msg("No username or groupname provided, running as the current user.")
		return nil, nil
	}

	if currentUid != 0 {
		log.Warn().Msg("Alpamon is not running as root. Falling back to the current user.")
		return nil, nil
	}

	usr, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("there is no corresponding %s username in this server", username)
	}

	group, err := user.LookupGroup(groupname)
	if err != nil {
		return nil, fmt.Errorf("there is no corresponding %s groupname in this server", groupname)
	}

	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return nil, err
	}

	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return nil, err
	}

	groupIds, err := usr.GroupIds()
	if err != nil {
		return nil, err
	}

	groups := make([]uint32, 0, len(groupIds))
	for _, gidStr := range groupIds {
		gidInt, err := strconv.Atoi(gidStr)
		if err != nil {
			return nil, err
		}
		groups = append(groups, uint32(gidInt))
	}

	log.Debug().Msgf("Demote permission to match user: %s, group: %s.", username, groupname)

	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uint32(uid),
			Gid:    uint32(gid),
			Groups: groups,
		},
	}, nil
}

func runCmdWithOutput(args []string, username, groupname string, env map[string]string, timeout int) (exitCode int, result string) {
	if env != nil {
		defaultEnv := getDefaultEnv()
		for key, value := range defaultEnv {
			if _, exists := env[key]; !exists {
				env[key] = value
			}
		}
		for i := range args {
			if strings.HasPrefix(args[i], "${") && strings.HasSuffix(args[i], "}") {
				varName := args[i][2 : len(args[i])-1]
				if val, ok := env[varName]; ok {
					args[i] = val
				}
			} else if strings.HasPrefix(args[i], "$") {
				varName := args[i][1:]
				if val, ok := env[varName]; ok {
					args[i] = val
				}
			}
		}
	}

	var ctx context.Context
	var cancel context.CancelFunc

	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	if username != "root" {
		sysProcAttr, err := demote(username, groupname)
		if err != nil {
			log.Error().Err(err).Msg("Failed to demote user.")
			return -1, err.Error()
		}
		if sysProcAttr != nil {
			cmd.SysProcAttr = sysProcAttr
		}
	}

	for key, value := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	usr, err := utils.GetSystemUser(username)
	if err != nil {
		return 1, err.Error()
	}
	cmd.Dir = usr.HomeDir

	log.Debug().Msgf("Executing command as user '%s' (group: '%s') -> '%s'", username, groupname, strings.Join(args, " "))
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode(), string(output)
		}
		return -1, err.Error()
	}

	return 0, string(output)
}
