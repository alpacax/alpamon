package tunnel

// OpenTunnelData contains data for opening a tunnel
type OpenTunnelData struct {
	SessionID  string `json:"session_id" validate:"required"`
	URL        string `json:"url" validate:"required"`
	ClientType string `json:"client_type" validate:"required,oneof=cli web editor"`
	TargetPort int    `json:"target_port"`  // Required for cli/web, ignored for editor
	Username   string `json:"username"`     // Required for editor
	Groupname  string `json:"groupname"`    // Optional for editor
}

// CloseTunnelData contains data for closing a tunnel
type CloseTunnelData struct {
	SessionID string `json:"session_id" validate:"required"`
}
