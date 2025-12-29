package tunnel

import (
	"github.com/alpacax/alpamon/pkg/runner"
	"github.com/spf13/cobra"
)

// TunnelWorkerCmd is the subcommand for running the tunnel worker subprocess.
// It is invoked by the main alpamon process with demoted user credentials.
var TunnelWorkerCmd = &cobra.Command{
	Use:   "tunnel-worker <targetAddr>",
	Short: "Tunnel worker subprocess for TCP relay",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetAddr := args[0] // e.g., "127.0.0.1:3306"
		runner.RunTunnelWorker(targetAddr)
	},
}
