package plugin

import (
	"context"
	"strings"
	"testing"
)

func validPlugin() Plugin {
	return Plugin{
		Name:           "alpamon-test-plugin",
		Version:        "test",
		WSPath:         "/ws/test/",
		CheckServerURL: "/api/test/-/",
		Build: func(context.Context, Host) (*BuildResult, error) {
			return &BuildResult{Run: func(context.Context) {}}, nil
		},
	}
}

func TestValidate(t *testing.T) {
	build := func(context.Context, Host) (*BuildResult, error) { return nil, nil }
	tests := []struct {
		name string
		p    Plugin
		want string
	}{
		{"missing name", Plugin{Version: "v1", WSPath: "/x", CheckServerURL: "/y", Build: build}, "Name"},
		{"missing version", Plugin{Name: "p", WSPath: "/x", CheckServerURL: "/y", Build: build}, "Version"},
		{"missing wspath", Plugin{Name: "p", Version: "v1", CheckServerURL: "/y", Build: build}, "WSPath"},
		{"missing check url", Plugin{Name: "p", Version: "v1", WSPath: "/x", Build: build}, "CheckServerURL"},
		{"missing build", Plugin{Name: "p", Version: "v1", WSPath: "/x", CheckServerURL: "/y"}, "Build"},
		{"complete", Plugin{Name: "p", Version: "v1", WSPath: "/x", CheckServerURL: "/y", Build: build}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("expected nil error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestNewRootCmdValid(t *testing.T) {
	p := validPlugin()
	cmd := NewRootCmd(&p)
	if cmd == nil {
		t.Fatal("NewRootCmd returned nil")
	}
	if cmd.Use != p.Name {
		t.Fatalf("cmd.Use = %q, want %q", cmd.Use, p.Name)
	}
	// The shared `setup` subcommand must be wired up so plugins can run
	// `<binary> setup` for first-time configuration.
	var hasSetup bool
	for _, sub := range cmd.Commands() {
		if sub.Use == "setup" {
			hasSetup = true
			break
		}
	}
	if !hasSetup {
		t.Fatal("expected `setup` subcommand to be registered")
	}
}

func TestNewRootCmdPanicsOnInvalidPlugin(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected NewRootCmd to panic on invalid Plugin")
		}
		err, ok := r.(error)
		if !ok || !strings.Contains(err.Error(), "Name") {
			t.Fatalf("expected error mentioning Name, got %v", r)
		}
	}()
	NewRootCmd(&Plugin{}) // missing required fields
}

func TestNewRootCmdPanicsOnNilPlugin(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected NewRootCmd to panic on nil Plugin")
		}
		s, ok := r.(string)
		if !ok || !strings.Contains(s, "nil Plugin") {
			t.Fatalf("expected panic message mentioning nil Plugin, got %v", r)
		}
	}()
	NewRootCmd(nil)
}
