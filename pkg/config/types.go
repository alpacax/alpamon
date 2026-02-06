package config

type Settings struct {
	ServerURL     string
	WSPath        string
	ControlWSPath string
	UseSSL        bool
	CaCert        string // CA certificate file path
	SSLVerify     bool
	SSLOpt        map[string]interface{}
	HTTPThreads   int
	ID            string
	Key           string
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
}
