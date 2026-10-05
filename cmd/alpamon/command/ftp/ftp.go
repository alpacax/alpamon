package ftp

import (
	"errors"
	"io"
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
			data, err := configData(cmd, args, os.Stdin)
			if err != nil {
				log.Error().Err(err).Msg("FTP worker aborting: invalid TLS settings")
				os.Exit(1)
			}
			RunFtpWorker(data)
		},
	}
	cmd.Flags().Bool(runner.FtpSSLVerifyFlag, true, "verify the server certificate")
	cmd.Flags().Bool(runner.FtpCACertStdinFlag, false, "read the CA certificate from standard input")
	return cmd
}

// configData reads the worker's arguments. The worker does not load the
// agent's configuration, so the agent passes its SSL verify setting as a flag
// and its CA certificate, by content, on stdin.
func configData(cmd *cobra.Command, args []string, stdin io.Reader) (runner.FtpConfigData, error) {
	sslVerify, _ := cmd.Flags().GetBool(runner.FtpSSLVerifyFlag)
	caOnStdin, _ := cmd.Flags().GetBool(runner.FtpCACertStdinFlag)

	var caCertPEM []byte
	if caOnStdin {
		data, err := runner.ReadCACertLimited(stdin)
		if err != nil {
			return runner.FtpConfigData{}, err
		}
		if len(data) == 0 {
			return runner.FtpConfigData{}, errors.New("no CA certificate on stdin")
		}
		caCertPEM = data
	}
	return runner.FtpConfigData{
		URL:           args[0],
		ServerURL:     args[1],
		HomeDirectory: args[2],
		Logger:        logger.NewFtpLogger(),
		SkipSSLVerify: !sslVerify,
		CaCertPEM:     caCertPEM,
	}, nil
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
	if err := ftpClient.RunFtpBackground(); err != nil {
		log.Error().Err(err).Msg("FTP worker aborting: could not open the session")
		os.Exit(1)
	}
}
