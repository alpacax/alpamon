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
// It takes the source path rather than an inherited descriptor: opening it
// here is what keeps the agent from resolving a path the requesting user
// controls. See utils.RunExtractWorker.
var ExtractCmd = &cobra.Command{
	Use:          "extract <srcPath> <destDir>",
	Short:        "Extract worker subprocess for WebFTP allow_unzip",
	Args:         cobra.ExactArgs(2),
	SilenceUsage: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(utils.RunExtractWorker(args[0], args[1], os.Stderr))
	},
}
