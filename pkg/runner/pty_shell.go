package runner

import (
	"slices"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

// resolveShell picks the shell to launch for a PTY session. A non-empty
// requested shell is used with no extra args when it appears in the host's
// valid login shells; otherwise the platform default shell and its default
// args are used. Requested shells run without DefaultShellArgs because those
// flags (-il / -NoLogo) are bash/zsh/powershell-specific and break other
// shells (dash, tcsh, cmd.exe).
func resolveShell(requested string, valid []string) (shell string, args []string) {
	if requested != "" {
		if slices.Contains(valid, requested) {
			return requested, nil
		}
		log.Warn().Str("requested", requested).
			Msg("Requested shell not in valid shells; falling back to default.")
	}
	return utils.DefaultShell(), utils.DefaultShellArgs()
}
