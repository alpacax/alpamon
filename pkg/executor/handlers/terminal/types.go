package terminal

// PTYData contains data for PTY operations
type PTYData struct {
	SessionID     string `json:"session_id" validate:"required"`
	URL           string `json:"url" validate:"required"`
	Username      string `json:"username" validate:"required"`
	Groupname     string `json:"groupname"`
	HomeDirectory string `json:"home_directory"`
	Rows          int    `json:"rows"`
	Cols          int    `json:"cols"`
}

// FTPData contains data for FTP operations
type FTPData struct {
	SessionID     string `json:"session_id" validate:"required"`
	URL           string `json:"url" validate:"required"`
	Username      string `json:"username" validate:"required"`
	Groupname     string `json:"groupname"`
	HomeDirectory string `json:"home_directory"`
}

// ResizePTYData contains data for resizing PTY
type ResizePTYData struct {
	SessionID string `json:"session_id" validate:"required"`
	Rows      int    `json:"rows" validate:"required"`
	Cols      int    `json:"cols" validate:"required"`
}
