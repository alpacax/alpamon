package ftp

import (
	"os"

	"github.com/alpacax/alpamon/v2/pkg/logger"
	"github.com/alpacax/alpamon/v2/pkg/runner"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var FtpCmd = newFtpCmd()

func newFtpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ftp [flags] <url> <serverURL> <homeDirectory>",
		Short: "Start worker for Web FTP",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			RunFtpWorker(configData(cmd, args))
		},
	}
	cmd.Flags().Bool(runner.FtpSSLVerifyFlag, true, "verify the server certificate")
	return cmd
}

// configData reads the worker's arguments. The worker does not load the
// agent's configuration, so the agent passes its SSL verify setting as a flag
// and its CA certificate, by content, in the environment.
func configData(cmd *cobra.Command, args []string) runner.FtpConfigData {
	sslVerify, _ := cmd.Flags().GetBool(runner.FtpSSLVerifyFlag)
	var caCertPEM []byte
	if v := os.Getenv(runner.FtpCaCertEnv); v != "" {
		caCertPEM = []byte(v)
	}
	return runner.FtpConfigData{
		URL:           args[0],
		ServerURL:     args[1],
		HomeDirectory: args[2],
		Logger:        logger.NewFtpLogger(),
		SkipSSLVerify: !sslVerify,
		CaCertPEM:     caCertPEM,
	}
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
