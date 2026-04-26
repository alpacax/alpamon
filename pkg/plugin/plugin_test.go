package plugin

import (
	"context"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	build := func(context.Context, Host) (*BuildResult, error) { return nil, nil }
	tests := []struct {
		name string
		p    Plugin
		want string
	}{
		{"missing name", Plugin{WSPath: "/x", CheckServerURL: "/y", Build: build}, "Name"},
		{"missing wspath", Plugin{Name: "p", CheckServerURL: "/y", Build: build}, "WSPath"},
		{"missing check url", Plugin{Name: "p", WSPath: "/x", Build: build}, "CheckServerURL"},
		{"missing build", Plugin{Name: "p", WSPath: "/x", CheckServerURL: "/y"}, "Build"},
		{"complete", Plugin{Name: "p", WSPath: "/x", CheckServerURL: "/y", Build: build}, ""},
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
