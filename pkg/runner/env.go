package runner

import (
	"github.com/alpacax/alpamon/v2/pkg/utils"
)

func getDefaultEnv() map[string]string {
	env := make(map[string]string)
	env["TERM"] = "xterm-256color"
	env["LS_COLORS"] = utils.DefaultLSColors
	env["LANG"] = "en_US.UTF-8"
	env["PATH"] = utils.DefaultPath()

	utils.LoadEtcEnvironment(env)

	return env
}
