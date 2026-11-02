package utils

import (
	"os"
	"runtime"
	"strings"
)

// MinimalChildEnvironment builds the identity and locale environment for a child.
func MinimalChildEnvironment(home, username string) []string {
	lang := os.Getenv("LANG")
	if lang == "" {
		lang = "C.UTF-8"
	}
	env := []string{"HOME=" + home,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=" + lang}
	if username != "" {
		env = append(env, "USER="+username, "LOGNAME="+username)
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "LC_") {
			env = append(env, entry)
		}
	}
	return env
}

// WithoutPluginEnvironment preserves inherited settings except plugin variables.
func WithoutPluginEnvironment() []string {
	env := []string{}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if runtime.GOOS == "windows" {
			key = strings.ToUpper(key)
		}
		if !strings.HasPrefix(key, "PLUGIN_") {
			env = append(env, entry)
		}
	}
	return env
}
