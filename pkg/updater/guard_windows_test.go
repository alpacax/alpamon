package updater

import (
	"testing"

	"golang.org/x/sys/windows/svc/mgr"
)

func TestFirstActionRestarts(t *testing.T) {
	tests := []struct {
		name    string
		actions []mgr.RecoveryAction
		want    bool
	}{
		{"no actions configured", nil, false},
		{"register default: restart first", []mgr.RecoveryAction{
			{Type: mgr.ServiceRestart}, {Type: mgr.ServiceRestart}, {Type: mgr.NoAction},
		}, true},
		{"noaction first, restart later", []mgr.RecoveryAction{
			{Type: mgr.NoAction}, {Type: mgr.ServiceRestart},
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstActionRestarts(tt.actions); got != tt.want {
				t.Errorf("firstActionRestarts() = %v, want %v", got, tt.want)
			}
		})
	}
}
