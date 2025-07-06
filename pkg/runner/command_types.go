package runner

import (
	"github.com/alpacax/alpamon/pkg/scheduler"
	"gopkg.in/go-playground/validator.v9"
)

type Content struct {
	Query   string  `json:"query"`
	Command Command `json:"command,omitempty"`
	Reason  string  `json:"reason,omitempty"`
}

type Command struct {
	ID    string            `json:"id"`
	Shell string            `json:"shell"`
	Line  string            `json:"line"`
	User  string            `json:"user"`
	Group string            `json:"group"`
	Env   map[string]string `json:"env"`
	Data  string            `json:"data,omitempty"`
}

type File struct {
	Username       string `json:"username"`
	Groupname      string `json:"groupname"`
	Type           string `json:"type"`
	Content        string `json:"content"`
	Path           string `json:"path"`
	AllowOverwrite bool   `json:"allow_overwrite"`
	AllowUnzip     bool   `json:"allow_unzip"`
	URL            string `json:"url"`
}

type CommandData struct {
	SessionID               string   `json:"session_id"`
	URL                     string   `json:"url"`
	Rows                    uint16   `json:"rows"`
	Cols                    uint16   `json:"cols"`
	Username                string   `json:"username"`
	Groupname               string   `json:"groupname"`
	Groupnames              []string `json:"groupnames"`
	HomeDirectory           string   `json:"home_directory"`
	HomeDirectoryPermission string   `json:"home_directory_permission"`
	UID                     uint64   `json:"uid"`
	GID                     uint64   `json:"gid"`
	Comment                 string   `json:"comment"`
	Shell                   string   `json:"shell"`
	Groups                  []uint64 `json:"groups"`
	Type                    string   `json:"type"`
	Content                 string   `json:"content"`
	Path                    string   `json:"path"`
	Paths                   []string `json:"paths"`
	Files                   []File   `json:"files,omitempty"`
	AllowOverwrite          bool     `json:"allow_overwrite,omitempty"`
	AllowUnzip              bool     `json:"allow_unzip,omitempty"`
	UseBlob                 bool     `json:"use_blob,omitempty"`
	Keys                    []string `json:"keys"`
}

type CommandRunner struct {
	name       string
	command    Command
	wsClient   *WebsocketClient
	apiSession *scheduler.Session
	data       CommandData
	validator  *validator.Validate
}

// Structs defining the required input data for command validation purposes. //

type addUserData struct {
	Username                string `validate:"required"`
	UID                     uint64 `validate:"required"`
	GID                     uint64 `validate:"required"`
	Comment                 string `validate:"required"`
	HomeDirectory           string `validate:"required"`
	HomeDirectoryPermission string `validate:"omitempty"` // Use omitempty for backward compatibility
	Shell                   string `validate:"required"`
	Groupname               string `validate:"required"`
}

type addGroupData struct {
	Groupname string `validate:"required"`
	GID       uint64 `validate:"required"`
}

type deleteUserData struct {
	Username string `validate:"required"`
}

type deleteGroupData struct {
	Groupname string `validate:"required"`
}

type modUserData struct {
	Username   string   `validate:"required"`
	Groupnames []string `validate:"required"`
	Comment    string   `validate:"required"`
}

type openPtyData struct {
	SessionID     string `validate:"required"`
	URL           string `validate:"required"`
	Username      string `validate:"required"`
	Groupname     string `validate:"required"`
	HomeDirectory string `validate:"required"`
	Rows          uint16 `validate:"required"`
	Cols          uint16 `validate:"required"`
}

type openFtpData struct {
	SessionID     string `validate:"required"`
	URL           string `validate:"required"`
	Username      string `validate:"required"`
	Groupname     string `validate:"required"`
	HomeDirectory string `validate:"required"`
}

type commandFin struct {
	Success     bool    `json:"success"`
	Result      string  `json:"result"`
	ElapsedTime float64 `json:"elapsed_time"`
}

type commandStat struct {
	Success bool         `json:"success"`
	Message string       `json:"message"`
	Type    transferType `json:"type"`
}

type transferType string

const (
	DOWNLOAD transferType = "download"
	UPLOAD   transferType = "upload"
)

var nonZipExt = map[string]bool{
	".jar":   true,
	".war":   true,
	".ear":   true,
	".apk":   true,
	".xpi":   true,
	".vsix":  true,
	".crx":   true,
	".egg":   true,
	".whl":   true,
	".appx":  true,
	".msix":  true,
	".ipk":   true,
	".nupkg": true,
	".kmz":   true,
}
