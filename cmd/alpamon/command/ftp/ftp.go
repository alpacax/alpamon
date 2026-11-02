package ftp

import (
	"bytes"
	"encoding/json"
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
		Use:   "ftp [flags] <serverURL> <homeDirectory>",
		Short: "Start worker for Web FTP",
		Args:  cobra.RangeArgs(2, 3),
		Run: func(cmd *cobra.Command, args []string) {
			data, err := configData(cmd, args, os.Stdin)
			if err != nil {
				log.Error().Err(err).Msg("FTP worker aborting: invalid worker configuration")
				os.Exit(1)
			}
			RunFtpWorker(data)
		},
	}
	cmd.Flags().Bool(runner.FtpSSLVerifyFlag, true, "verify the server certificate")
	cmd.Flags().Bool(runner.FtpCACertStdinFlag, false, "read worker connection settings from standard input")
	return cmd
}

// configData reads the worker's arguments. The worker does not load the
// agent's configuration, so the agent passes its connection settings on stdin.
func configData(cmd *cobra.Command, args []string, stdin io.Reader) (runner.FtpConfigData, error) {
	sslVerify, _ := cmd.Flags().GetBool(runner.FtpSSLVerifyFlag)
	caOnStdin, _ := cmd.Flags().GetBool(runner.FtpCACertStdinFlag)

	legacy := !caOnStdin
	var settings runner.FtpWorkerConfig
	settings.Connection.UseEnvironment = !caOnStdin
	if caOnStdin {
		data, err := io.ReadAll(io.LimitReader(stdin, 2*runner.MaxFtpCACertSize+1))
		if closer, ok := stdin.(io.Closer); ok {
			_ = closer.Close()
		}
		// The payload can carry proxy credentials; drop the raw copy once parsed.
		defer clear(data)
		if err != nil {
			return runner.FtpConfigData{}, err
		}
		if len(data) > 2*runner.MaxFtpCACertSize {
			return runner.FtpConfigData{}, errors.New("worker configuration larger than limit")
		}
		if len(data) == 0 {
			return runner.FtpConfigData{}, errors.New("no worker configuration on stdin")
		}
		if bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
			if err := json.Unmarshal(data, &settings); err != nil {
				return runner.FtpConfigData{}, errors.New("invalid worker configuration on stdin")
			}
			legacy = settings.URL == ""
		} else {
			legacy = true
			settings.CaCertPEM = bytes.Clone(data)
			settings.Connection.UseEnvironment = true
		}
		if len(settings.CaCertPEM) > runner.MaxFtpCACertSize {
			return runner.FtpConfigData{}, errors.New("CA certificate larger than limit")
		}
	}
	if legacy {
		if len(args) != 3 {
			return runner.FtpConfigData{}, errors.New("previous worker format requires a session URL argument")
		}
		settings.URL = args[0]
		args = args[1:]
	} else if len(args) != 2 || settings.URL == "" {
		return runner.FtpConfigData{}, errors.New("invalid worker configuration arguments")
	}
	return runner.FtpConfigData{
		URL:           settings.URL,
		ServerURL:     args[0],
		HomeDirectory: args[1],
		Logger:        logger.NewFtpLogger(),
		SkipSSLVerify: !sslVerify,
		CaCertPEM:     settings.CaCertPEM,
		Connection:    settings.Connection,
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
