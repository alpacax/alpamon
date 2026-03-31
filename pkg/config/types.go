package config

type Settings struct {
	ServerURL          string
	WSPath             string
	ControlWSPath      string
	UseSSL             bool
	CaCert             string // CA certificate file path
	SSLVerify          bool
	SSLOpt             map[string]interface{}
	HTTPThreads        int
	ID                 string
	Key                string
	PoolMaxWorkers     int // Maximum number of workers in the global worker pool
	PoolQueueSize      int // Size of the job queue for the global worker pool
	PoolDefaultTimeout int // Default timeout in seconds for pool tasks (0 = no timeout)
	EditorIdleTimeout  int // Editor idle timeout in minutes (0 = no timeout)

	// Command signature verification
	AIServerURL    string // AI server URL for public key fetch (empty = verification disabled)
	SigningMode    string // "monitor" (warn only) or "enforce" (reject unsigned)
	KeyRefreshSecs int    // Public key cache TTL in seconds
}

type Config struct {
	Server struct {
		URL string `ini:"url"`
		ID  string `ini:"id"`
		Key string `ini:"key"`
	} `ini:"server"`
	SSL struct {
		Verify bool   `ini:"verify"`
		CaCert string `ini:"ca_cert"`
	} `ini:"ssl"`
	Logging struct {
		Debug bool `ini:"debug"`
	} `ini:"logging"`
	Pool struct {
		MaxWorkers     int  `ini:"max_workers"`
		QueueSize      int  `ini:"queue_size"`
		DefaultTimeout *int `ini:"default_timeout"`
	} `ini:"pool"`
	Editor struct {
		IdleTimeout *int `ini:"idle_timeout"`
	} `ini:"editor"`
	Signing struct {
		AIServerURL string `ini:"ai_server_url"`
		Mode        string `ini:"mode"`
		KeyRefresh  *int   `ini:"key_refresh"`
	} `ini:"signing"`
}
