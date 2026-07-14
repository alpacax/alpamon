package runner

import (
	"runtime"
	"slices"
	"strings"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

// resolveShell picks the shell to launch for a PTY session. A requested shell
// runs without DefaultShellArgs because those flags (-il / -NoLogo) are
// bash/zsh/powershell-specific and break other shells (dash, tcsh, cmd.exe).
func resolveShell(requested string, validShells []string) (shell string, args []string) {
	if requested != "" {
		if shellAllowed(requested, validShells, runtime.GOOS == "windows") {
			return requested, nil
		}
		log.Warn().Str("requested", requested).
			Msg("Requested shell not in valid shells; falling back to default.")
	}
	return utils.DefaultShell(), utils.DefaultShellArgs()
}

// caseInsensitive is set on Windows, where executable names are case-insensitive.
func shellAllowed(requested string, validShells []string, caseInsensitive bool) bool {
	if caseInsensitive {
		return slices.ContainsFunc(validShells, func(s string) bool {
			return strings.EqualFold(s, requested)
		})
	}
	return slices.Contains(validShells, requested)
}
