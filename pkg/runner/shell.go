package runner

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

func demote(username, groupname string) (*syscall.SysProcAttr, error) {
	result, err := utils.Demote(username, groupname, utils.DemoteOptions{ValidateGroup: true})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.SysProcAttr, nil
}

func demoteWithHomeDir(username, groupname string) (*syscall.SysProcAttr, string, error) {
	result, err := utils.Demote(username, groupname, utils.DemoteOptions{ValidateGroup: false})
	if err != nil {
		return nil, "", err
	}
	if result == nil {
		return nil, "", nil
	}
	return result.SysProcAttr, result.User.HomeDir, nil
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
