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
	"gopkg.in/ini.v1"
)

var (
	GlobalSettings Settings
)

const (
	MinConnectInterval = 5 * time.Second
	MaxConnectInterval = 300 * time.Second

	// Pool configuration defaults
	DefaultPoolMaxWorkers     = 20
	DefaultPoolQueueSize      = 200
	DefaultPoolDefaultTimeout = 30

	// Pool configuration limits for warnings
	MaxReasonableWorkers       = 1000
	MaxReasonableQueueSize     = 10000
	MaxReasonableTimeoutSeconds = 3600
)

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
		WSPath:             wsPath,
		UseSSL:             false,
		SSLVerify:          true,
		SSLOpt:             make(map[string]interface{}),
		HTTPThreads:        4,
		PoolMaxWorkers:     DefaultPoolMaxWorkers,
		PoolQueueSize:      DefaultPoolQueueSize,
		PoolDefaultTimeout: DefaultPoolDefaultTimeout,
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

	// Validate and set worker pool configuration
	if config.Pool.MaxWorkers > 0 {
		settings.PoolMaxWorkers = config.Pool.MaxWorkers
		log.Debug().Msgf("Using configured pool max workers: %d", settings.PoolMaxWorkers)
	} else {
		log.Debug().Msgf("Using default pool max workers: %d", settings.PoolMaxWorkers)
	}

	if config.Pool.QueueSize > 0 {
		settings.PoolQueueSize = config.Pool.QueueSize
		log.Debug().Msgf("Using configured pool queue size: %d", settings.PoolQueueSize)
	} else {
		log.Debug().Msgf("Using default pool queue size: %d", settings.PoolQueueSize)
	}

	// Validate and set default timeout for pool tasks
	// Use pointer type to distinguish "not configured" (nil) from "explicitly set to 0"
	if config.Pool.DefaultTimeout != nil {
		settings.PoolDefaultTimeout = *config.Pool.DefaultTimeout
		if settings.PoolDefaultTimeout == 0 {
			log.Debug().Msg("Using configured pool default timeout: 0 (no timeout)")
		} else {
			log.Debug().Msgf("Using configured pool default timeout: %d seconds", settings.PoolDefaultTimeout)
		}
	} else {
		// Keep the default value that was set during Settings initialization
		log.Debug().Msgf("Using default pool timeout: %d seconds", settings.PoolDefaultTimeout)
	}

	// Validate pool settings are reasonable
	if settings.PoolMaxWorkers > MaxReasonableWorkers {
		log.Warn().Msgf("Pool max workers (%d) seems very high, consider reducing it", settings.PoolMaxWorkers)
	}
	if settings.PoolQueueSize > MaxReasonableQueueSize {
		log.Warn().Msgf("Pool queue size (%d) seems very high, consider reducing it", settings.PoolQueueSize)
	}
	if settings.PoolDefaultTimeout > MaxReasonableTimeoutSeconds {
		log.Warn().Msgf("Pool default timeout (%d seconds) seems very high, consider reducing it", settings.PoolDefaultTimeout)
	}

	return valid, settings
}

func Files(name string) []string {
	return []string{
		fmt.Sprintf("/etc/alpamon/%s.conf", name),
		filepath.Join(os.Getenv("HOME"), fmt.Sprintf(".%s.conf", name)),
	}
}
