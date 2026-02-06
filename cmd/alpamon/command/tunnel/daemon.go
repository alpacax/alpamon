package tunnel

import (
	"github.com/alpacax/alpamon/pkg/runner"
	"github.com/spf13/cobra"
)

// TunnelDaemonCmd is the subcommand for running the tunnel daemon subprocess.
// It is invoked by the main alpamon process with demoted user credentials.
var TunnelDaemonCmd = &cobra.Command{
	Use:   "tunnel-daemon <socketPath>",
	Short: "Tunnel daemon subprocess for multiplexed TCP relay",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		socketPath := args[0]
		runner.RunTunnelDaemon(socketPath)
	},
}
