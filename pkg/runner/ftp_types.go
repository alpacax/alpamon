package runner

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/logger"
	"github.com/alpacax/alpamon/v2/pkg/utils"
)

type FtpCommand string

const (
	List  FtpCommand = "list"
	Mkd   FtpCommand = "mkd"
	Cwd   FtpCommand = "cwd"
	Pwd   FtpCommand = "pwd"
	Dele  FtpCommand = "dele"
	Rmd   FtpCommand = "rmd"
	Mv    FtpCommand = "mv"
	Cp    FtpCommand = "cp"
	Chmod FtpCommand = "chmod"
	Chown FtpCommand = "chown"
)

const (
	ErrPermissionDenied      = "permission denied"
	ErrOperationNotPermitted = "operation not permitted"
	ErrTooLargeDepth         = "depth has reached its limit. please try a lower depth"
	ErrInvalidArgument       = "invalid argument"
	ErrNoSuchFileOrDirectory = "no such file or directory"
	ErrFileExists            = "file exists"
	ErrDirectoryNotEmpty     = "directory not empty"
	ErrInfiniteRecursion     = "causing infinite recursion"
	ErrNotSupported          = "not supported on this platform"
)

type FtpConfigData struct {
	URL           string
	ServerURL     string
	HomeDirectory string
	Logger        logger.FtpLogger
	// SkipSSLVerify turns off server certificate verification. The zero
	// value verifies, matching the agent's default.
	SkipSSLVerify bool
	// CaCertPEM contains the trust bundle read by the agent.
	CaCertPEM  []byte
	Connection FtpConnectionConfig
}

type FtpData struct {
	Path           string `json:"path,omitempty"`
	Depth          int    `json:"depth,omitempty"`
	Recursive      bool   `json:"recursive,omitempty"`
	ShowHidden     bool   `json:"show_hidden,omitempty"`
	AllowOverwrite bool   `json:"allow_overwrite,omitempty"`
	Src            string `json:"src,omitempty"`
	Dst            string `json:"dst,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Username       string `json:"username,omitempty"`
	Groupname      string `json:"groupname,omitempty"`
}

type FtpContent struct {
	Command FtpCommand `json:"command"`
	Data    FtpData    `json:"data"`
}

type FtpResult struct {
	Command FtpCommand    `json:"command"`
	Success bool          `json:"success"`
	Code    int           `json:"code,omitempty"`
	Data    CommandResult `json:"data"`
}

type CommandResult struct {
	Name             string          `json:"name,omitempty"`
	Type             string          `json:"type,omitempty"`
	Path             string          `json:"path,omitempty"`
	Dst              string          `json:"dst,omitempty"`
	Code             int             `json:"code,omitempty"`
	Size             int64           `json:"size,omitempty"`
	Children         []CommandResult `json:"children,omitempty"`
	ModTime          *time.Time      `json:"mod_time,omitempty"`
	Message          string          `json:"message,omitempty"`
	PermissionString string          `json:"permission_str,omitempty"`
	PermissionOctal  string          `json:"permission_octal,omitempty"`
	Owner            string          `json:"owner,omitempty"`
	Group            string          `json:"group,omitempty"`
	Target           string          `json:"target,omitempty"` // Symlink target path
}

type returnCode struct {
	Success int            `json:"success"`
	Error   map[string]int `json:"error"`
}

var returnCodes = map[FtpCommand]returnCode{
	List: {
		Success: 250,
		Error: map[string]int{
			ErrPermissionDenied:      450,
			ErrOperationNotPermitted: 450,
			ErrTooLargeDepth:         452,
			ErrNoSuchFileOrDirectory: 550,
		},
	},
	Mkd: {
		Success: 250,
		Error: map[string]int{
			ErrPermissionDenied:      450,
			ErrOperationNotPermitted: 450,
			ErrInvalidArgument:       452,
			ErrNoSuchFileOrDirectory: 550,
			ErrFileExists:            552,
		},
	},
	Cwd: {
		Success: 250,
		Error: map[string]int{
			ErrPermissionDenied:      450,
			ErrOperationNotPermitted: 450,
			ErrNoSuchFileOrDirectory: 550,
		},
	},
	Pwd: {
		Success: 250,
		Error: map[string]int{
			ErrPermissionDenied:      450,
			ErrOperationNotPermitted: 450,
			ErrNoSuchFileOrDirectory: 550,
		},
	},
	Dele: {
		Success: 250,
		Error: map[string]int{
			ErrPermissionDenied:      450,
			ErrOperationNotPermitted: 450,
			ErrInvalidArgument:       452,
			ErrNoSuchFileOrDirectory: 550,
		},
	},
	Rmd: {
		Success: 250,
		Error: map[string]int{
			ErrPermissionDenied:      450,
			ErrOperationNotPermitted: 450,
			ErrInvalidArgument:       452,
			ErrNoSuchFileOrDirectory: 550,
			ErrDirectoryNotEmpty:     552,
		},
	},
	Mv: {
		Success: 250,
		Error: map[string]int{
			ErrPermissionDenied:      450,
			ErrOperationNotPermitted: 450,
			ErrInvalidArgument:       452,
			ErrNoSuchFileOrDirectory: 550,
			ErrFileExists:            552,
		},
	},
	Cp: {
		Success: 250,
		Error: map[string]int{
			ErrPermissionDenied:      450,
			ErrOperationNotPermitted: 450,
			ErrInvalidArgument:       452,
			ErrNoSuchFileOrDirectory: 550,
			ErrFileExists:            552,
			ErrInfiniteRecursion:     553,
		},
	},
	Chmod: {
		Success: 250,
		Error: map[string]int{
			ErrPermissionDenied:      450,
			ErrOperationNotPermitted: 450,
			ErrInvalidArgument:       452,
			ErrNoSuchFileOrDirectory: 550,
			ErrNotSupported:          502,
		},
	},
	Chown: {
		Success: 250,
		Error: map[string]int{
			ErrPermissionDenied:      450,
			ErrOperationNotPermitted: 450,
			ErrInvalidArgument:       452,
			ErrNoSuchFileOrDirectory: 550,
			ErrNotSupported:          502,
		},
	},
}

func GetFtpErrorCode(command FtpCommand, result CommandResult) (CommandResult, int) {
	if codes, ok := returnCodes[command]; ok {
		for message, code := range codes.Error {
			if strings.Contains(result.Message, message) {
				return CommandResult{
					Message: result.Message,
				}, code
			}
		}
	}
	// Default error code if not found
	return CommandResult{
		Message: result.Message,
	}, 550
}

// FtpSSLVerifyFlag is the ftp worker flag that carries the agent's SSL verify
// setting.
const FtpSSLVerifyFlag = "ssl-verify"

// FtpCACertStdinFlag tells the worker to read its private connection configuration
// from stdin, including the CA certificate the session user may not be able to read.
const FtpCACertStdinFlag = "ca-cert-stdin"

// MaxFtpCACertSize caps the CA certificate passed to the ftp worker.
const MaxFtpCACertSize = 1 << 20 // 1 MiB

// FtpWorkerArgs returns the arguments that start the ftp worker for a session.
func FtpWorkerArgs(url, serverURL, homeDirectory string, sslVerify bool) []string {
	args := []string{"ftp", "--" + FtpSSLVerifyFlag + "=" + strconv.FormatBool(sslVerify)}
	args = append(args, "--"+FtpCACertStdinFlag)
	return append(args, "--", url, serverURL, homeDirectory)
}

// ReadFtpCACert reads the CA certificate at caCert for the ftp worker. An empty
// caCert returns nil.
func ReadFtpCACert(caCert string) ([]byte, error) {
	if caCert == "" {
		return nil, nil
	}
	f, err := os.Open(caCert)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}
	defer func() { _ = f.Close() }()
	return readCACertLimited(f)
}

// readCACertLimited reads a CA certificate of at most MaxFtpCACertSize bytes.
func readCACertLimited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxFtpCACertSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}
	if len(data) > MaxFtpCACertSize {
		return nil, fmt.Errorf("CA certificate is larger than %d bytes", MaxFtpCACertSize)
	}
	return data, nil
}

// FtpConnectionConfig carries resolved agent connection settings over stdin.
type FtpConnectionConfig struct {
	ProxyURL       string
	UseEnvironment bool `json:"-"`
}

// FtpWorkerConfig is the private stdin payload shared by the agent and worker.
type FtpWorkerConfig struct {
	CaCertPEM  []byte
	Connection FtpConnectionConfig
}

// ErrFtpProxyConfig reports an unusable proxy setting without its value, which can carry credentials.
var ErrFtpProxyConfig = errors.New("invalid proxy configuration")

// PrepareFtpWorkerConfig resolves connection settings before the worker is demoted.
func PrepareFtpWorkerConfig(target, caCert string) (FtpWorkerConfig, error) {
	var settings FtpWorkerConfig
	resolved, err := resolveWebSocketURL(target, config.GlobalSettings.ServerURL)
	if err != nil {
		return settings, fmt.Errorf("invalid session URL: %w", err)
	}
	req, err := http.NewRequest(http.MethodGet, resolved, nil)
	if err != nil {
		return settings, fmt.Errorf("invalid session URL: %w", err)
	}
	// Gorilla resolves proxies after converting the WebSocket URL to HTTP.
	switch req.URL.Scheme {
	case "wss":
		req.URL.Scheme = "https"
	case "ws":
		req.URL.Scheme = "http"
	}
	proxy, err := utils.WebsocketProxy(req)
	if err != nil {
		return settings, ErrFtpProxyConfig
	}
	if proxy != nil {
		settings.Connection.ProxyURL = proxy.String()
	}
	settings.CaCertPEM, err = ReadFtpCACert(caCert)
	if err != nil {
		return settings, err
	}
	return settings, nil
}
