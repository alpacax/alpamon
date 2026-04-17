package ftp

import (
	"os"

	"github.com/alpacax/alpamon/pkg/logger"
	"github.com/alpacax/alpamon/pkg/runner"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var FtpCmd = &cobra.Command{
	Use:   "ftp <url> <serverURL> <homeDirectory>",
	Short: "Start worker for Web FTP",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		data := runner.FtpConfigData{
			URL:           args[0],
			ServerURL:     args[1],
			HomeDirectory: args[2],
			Logger:        logger.NewFtpLogger(),
		}

		RunFtpWorker(data)
	},
}

func RunFtpWorker(data runner.FtpConfigData) {
	ftpClient := runner.NewFtpClient(data)
	if ftpClient == nil {
		// NewFtpClient refuses to start on Windows when the home
		// directory is empty, since containment requires a valid
		// root. Surface it as an error so the parent/operator can
		// spot the misconfiguration instead of a silent success.
		log.Error().Msg("FTP worker aborting: client could not be initialized")
		os.Exit(1)
	}
	ftpClient.RunFtpBackground()
}
