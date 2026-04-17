package ftp

import (
	"github.com/alpacax/alpamon/pkg/logger"
	"github.com/alpacax/alpamon/pkg/runner"
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
		return
	}
	ftpClient.RunFtpBackground()
}
