package config

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"text/template"

	"gopkg.in/ini.v1"
)

// confTemplate is the on-disk alpamon.conf layout ([server]/[ssl]/[logging];
// ca_cert is omitted when empty). Compiled once at init via template.Must — a
// parse failure here is a programmer error in this static template, not a
// runtime condition, so panicking at startup is appropriate.
var confTemplate = template.Must(template.New("conf").Parse(`[server]
url = {{ .URL }}
id = {{ .ID }}
key = {{ .Key }}

[ssl]
verify = {{ .Verify }}
{{- if .CACert }}
ca_cert = {{ .CACert }}
{{- end }}

[logging]
debug = false
`))

// ServerConfig is the [server] section of alpamon.conf: the identity and
// credentials an already-registered agent uses to authenticate back to Alpacon.
// It is embedded in Config so the on-disk schema is declared exactly once.
type ServerConfig struct {
	URL string `ini:"url"`
	ID  string `ini:"id"`
	Key string `ini:"key"`
}

// ReadServer parses path as INI and returns the [server] url/id/key. Unlike
// LoadConfig it returns a normal error (no log.Fatal) so callers on recovery
// paths (migrate, unregister) can degrade gracefully — e.g. treat a missing or
// malformed config as "nothing to clean up".
func ReadServer(path string) (*ServerConfig, error) {
	f, err := ini.Load(path)
	if err != nil {
		return nil, fmt.Errorf("parse conf: %w", err)
	}
	section, err := f.GetSection("server")
	if err != nil {
		return nil, errors.New("[server] section missing")
	}
	get := func(name string) string {
		k, err := section.GetKey(name)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(k.String())
	}
	s := &ServerConfig{URL: get("url"), ID: get("id"), Key: get("key")}
	if s.URL == "" {
		return nil, errors.New("url not found in [server] section")
	}
	if s.ID == "" || s.Key == "" {
		return nil, errors.New("id/key not found in [server] section")
	}
	return s, nil
}

// ReadSSL reads the [ssl] section (verify, ca_cert) from path. Best-effort: a
// missing file/section/key yields the secure default verify=true and no CA, so
// callers can use it as a sane TLS baseline. Recovery paths (unregister,
// register --force) use it so the DELETE to a server speaks that server's own
// TLS settings rather than whatever flags the current invocation defaulted to.
func ReadSSL(path string) (verify bool, caCert string) {
	verify = true
	f, err := ini.Load(path)
	if err != nil {
		return verify, ""
	}
	section, err := f.GetSection("ssl")
	if err != nil {
		return verify, ""
	}
	if k, err := section.GetKey("verify"); err == nil {
		if b, perr := k.Bool(); perr == nil {
			verify = b
		}
	}
	if k, err := section.GetKey("ca_cert"); err == nil {
		caCert = strings.TrimSpace(k.String())
	}
	return verify, caCert
}

// RenderConf produces the alpamon.conf body for the given server identity and
// SSL settings. It is the single source of truth for the on-disk config format,
// shared by register and migrate so the two cannot drift.
func RenderConf(s ServerConfig, sslVerify bool, caCertPath string) (string, error) {
	var buf bytes.Buffer
	if err := confTemplate.Execute(&buf, map[string]any{
		"URL":    s.URL,
		"ID":     s.ID,
		"Key":    s.Key,
		"Verify": sslVerify,
		"CACert": caCertPath,
	}); err != nil {
		return "", fmt.Errorf("render conf: %w", err)
	}
	return buf.String(), nil
}
