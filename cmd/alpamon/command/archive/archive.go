package archive

import (
	"os"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/spf13/cobra"
)

// ArchiveCmd is the subcommand for building a WebFTP download archive. It is
// invoked by the main alpamon process with demoted user credentials, so the
// directory walk and every file open below it are subject to the requesting
// user's filesystem permissions instead of the agent's root.
//
// stdout carries the archive and stderr carries the JSON status the parent
// parses, so usage output is silenced: a cobra usage dump on either stream
// would corrupt what the parent reads.
var ArchiveCmd = &cobra.Command{
	Use:          "archive",
	Short:        "Archive worker subprocess for WebFTP folder download",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(utils.RunArchiveWorker(os.Stdin, os.Stdout, os.Stderr))
	},
}
