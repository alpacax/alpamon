package config

import "os"

func configDir() string { return os.Getenv("ProgramData") + `\alpamon` }
