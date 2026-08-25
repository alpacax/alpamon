package extract

import (
	"os"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/spf13/cobra"
)

// ExtractCmd is the subcommand for the allow_unzip extraction. It is invoked
// by the main alpamon process with demoted user credentials, so the extracted
// files and directories belong to the requesting user and the extraction
// cannot write over paths that user could not have touched.
//
// The archive arrives on stdin as the descriptor the parent opened and
// validated, so this process never resolves the archive path itself.
var ExtractCmd = &cobra.Command{
	Use:          "extract <destDir>",
	Short:        "Extract worker subprocess for WebFTP allow_unzip",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(utils.RunExtractWorker(os.Stdin, args[0], os.Stderr))
	},
}
