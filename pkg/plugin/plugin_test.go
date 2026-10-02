package plugin

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
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
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestNewRootCmdValid(t *testing.T) {
	p := validPlugin()
	cmd := NewRootCmd(&p)
	require.NotNil(t, cmd, "NewRootCmd returned nil")
	require.Equal(t, p.Name, cmd.Use)
	// The shared `setup` subcommand must be wired up so plugins can run
	// `<binary> setup` for first-time configuration.
	var hasSetup bool
	for _, sub := range cmd.Commands() {
		if sub.Use == "setup" {
			hasSetup = true
			break
		}
	}
	require.True(t, hasSetup, "expected `setup` subcommand to be registered")
}

func TestNewRootCmdPanicsOnInvalidPlugin(t *testing.T) {
	defer func() {
		r := recover()
		require.NotNil(t, r, "expected NewRootCmd to panic on invalid Plugin")
		err, ok := r.(error)
		require.True(t, ok, "expected error, got %v", r)
		require.ErrorContains(t, err, "Name")
	}()
	NewRootCmd(&Plugin{}) // missing required fields
}

func TestNewRootCmdPanicsOnNilPlugin(t *testing.T) {
	defer func() {
		r := recover()
		require.NotNil(t, r, "expected NewRootCmd to panic on nil Plugin")
		s, ok := r.(string)
		require.True(t, ok, "expected string panic, got %v", r)
		require.Contains(t, s, "nil Plugin", "expected panic message mentioning nil Plugin")
	}()
	NewRootCmd(nil)
}
