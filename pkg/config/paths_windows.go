package config

import (
	"os"
	"path/filepath"
)

func configDir() string {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		dir = `C:\ProgramData`
	}
	return filepath.Join(dir, "alpamon")
}
