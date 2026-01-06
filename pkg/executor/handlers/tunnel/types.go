package tunnel

// OpenTunnelData contains data for opening a tunnel
type OpenTunnelData struct {
	SessionID  string `json:"session_id" validate:"required"`
	URL        string `json:"url" validate:"required"`
	TargetPort int    `json:"target_port" validate:"required,min=1,max=65535"`
}

// CloseTunnelData contains data for closing a tunnel
type CloseTunnelData struct {
	SessionID string `json:"session_id" validate:"required"`
}
