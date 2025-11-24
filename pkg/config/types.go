package config

type Settings struct {
	ServerURL          string
	WSPath             string
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
}
