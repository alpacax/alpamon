package file

const (
	fileUploadTimeout = 60 * 10 // 600 seconds
)

type transferType string

const (
	download transferType = "download"
	upload   transferType = "upload"
)

// commandStat represents the file transfer status payload
type commandStat struct {
	Success bool         `json:"success"`
	Message string       `json:"message"`
	Type    transferType `json:"type"`
}

// FileData contains data for file operations
type FileData struct {
	Username       string     `json:"username"`
	Groupname      string     `json:"groupname"`
	Paths          []string   `json:"paths,omitempty"`   // For upload
	Files          []FileInfo `json:"files,omitempty"`   // For batch download
	Path           string     `json:"path,omitempty"`    // Single file path
	Content        []byte     `json:"content,omitempty"` // File content for download
	Type           string     `json:"type,omitempty"`    // File type
	AllowOverwrite bool       `json:"allow_overwrite,omitempty"`
	AllowUnzip     bool       `json:"allow_unzip,omitempty"`
	URL            string     `json:"url,omitempty"`
}

// FileInfo contains information about a file for batch operations
type FileInfo struct {
	Username       string `json:"username"`
	Groupname      string `json:"groupname"`
	Path           string `json:"path"`
	Type           string `json:"type"`
	Content        []byte `json:"content"`
	AllowOverwrite bool   `json:"allow_overwrite"`
	AllowUnzip     bool   `json:"allow_unzip"`
	URL            string `json:"url"`
}
