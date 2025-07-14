package runner

import (
	"strings"
	"time"

	"github.com/alpacax/alpamon/pkg/logger"
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
)

type FtpConfigData struct {
	URL           string
	ServerURL     string
	HomeDirectory string
	Logger        logger.FtpLogger
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
	Data    CommandResult `json:"data,omitempty"`
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
		},
	},
	Chown: {
		Success: 250,
		Error: map[string]int{
			ErrPermissionDenied:      450,
			ErrOperationNotPermitted: 450,
			ErrInvalidArgument:       452,
			ErrNoSuchFileOrDirectory: 550,
		},
	},
}

func GetFtpErrorCode(command FtpCommand, result CommandResult) (CommandResult, int) {
	if codes, ok := returnCodes[command]; ok {
		for message, code := range codes.Error {
			if strings.Contains(result.Message, message) {
				return CommandResult{
					Message: message,
				}, code
			}
		}
	}
	// Default error code if not found
	return CommandResult{
		Message: result.Message,
	}, 550
}
