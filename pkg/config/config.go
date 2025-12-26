package config

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/xtaci/smux"
	"gopkg.in/ini.v1"
)

var (
	GlobalSettings Settings
)

const (
	MinConnectInterval    = 5 * time.Second
	MaxConnectInterval    = 300 * time.Second
	SmuxKeepAliveInterval = 10 * time.Second
	SmuxKeepAliveTimeout  = 30 * time.Second
	SmuxMaxFrameSize      = 32768   // 32KB
	SmuxMaxReceiveBuffer  = 4194304 // 4MB
	SmuxMaxStreamBuffer   = 65536   // 64KB per stream
)

// GetSmuxConfig returns optimized smux configuration for tunnel connections.
func GetSmuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()

	cfg.KeepAliveInterval = SmuxKeepAliveInterval
	cfg.KeepAliveTimeout = SmuxKeepAliveTimeout
	cfg.MaxFrameSize = SmuxMaxFrameSize
	cfg.MaxReceiveBuffer = SmuxMaxReceiveBuffer
	cfg.MaxStreamBuffer = SmuxMaxStreamBuffer

	return cfg
}

func InitSettings(settings Settings) {
	GlobalSettings = settings
}

func LoadConfig(configFiles []string, wsPath string) Settings {
	var iniData *ini.File
	var err error
	var validConfigFile string

	for _, configFile := range configFiles {
		fileInfo, statErr := os.Stat(configFile)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				continue
			} else {
				log.Error().Err(statErr).Msgf("Error accessing config file %s.", configFile)
				continue
			}
		}

		if fileInfo.Size() == 0 {
			log.Debug().Msgf("Config file %s is empty, skipping...", configFile)
			continue
		}

		log.Debug().Msgf("Using config file %s.", configFile)
		validConfigFile = configFile
		break
	}

	if validConfigFile == "" {
		log.Fatal().Msg("No valid config file found.")
	}

	iniData, err = ini.Load(validConfigFile)
	if err != nil {
		log.Fatal().Err(err).Msgf("failed to load config file %s.", validConfigFile)
	}

	var config Config
	err = iniData.MapTo(&config)
	if err != nil {
		log.Fatal().Err(err).Msgf("failed to parse config file %s.", validConfigFile)
	}

	if config.Logging.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	isValid, settings := validateConfig(config, wsPath)

	if !isValid {
		log.Fatal().Msg("Aborting...")
	}

	return settings
}

func validateConfig(config Config, wsPath string) (bool, Settings) {
	log.Debug().Msg("Validating configuration fields...")

	settings := Settings{
		WSPath:      wsPath,
		UseSSL:      false,
		SSLVerify:   true,
		SSLOpt:      make(map[string]interface{}),
		HTTPThreads: 4,
	}

	valid := true
	val := config.Server.URL
	if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
		val = strings.TrimSuffix(val, "/")
		settings.ServerURL = val
		settings.WSPath = strings.Replace(val, "http", "ws", 1) + settings.WSPath
		settings.WSPath = strings.Replace(settings.WSPath, "8000", "8081", 1) // just for local environment (not effected in prod)
		settings.UseSSL = strings.HasPrefix(val, "https://")
	} else {
		log.Error().Msg("Server url is invalid.")
		valid = false
	}

	if config.Server.ID != "" && config.Server.Key != "" {
		settings.ID = config.Server.ID
		settings.Key = config.Server.Key
	} else {
		log.Error().Msg("Server ID, KEY is empty.")
		valid = false
	}

	settings.SSLVerify = config.SSL.Verify
	if settings.UseSSL {
		caCert := config.SSL.CaCert
		if !settings.SSLVerify {
			log.Warn().Msg(
				"SSL verification is turned off. " +
					"Please be aware that this setting is not appropriate for production use.",
			)
			settings.SSLOpt["cert_reqs"] = &tls.Config{InsecureSkipVerify: true}
		} else if caCert != "" {
			if _, err := os.Stat(caCert); os.IsNotExist(err) {
				log.Error().Msg("Given path for CA certificate does not exist.")
				valid = false
			} else {
				settings.CaCert = caCert
				settings.SSLOpt["ca_certs"] = caCert
			}
		}
	}

	return valid, settings
}

func Files(name string) []string {
	return []string{
		fmt.Sprintf("/etc/alpamon/%s.conf", name),
		filepath.Join(os.Getenv("HOME"), fmt.Sprintf(".%s.conf", name)),
	}
}
