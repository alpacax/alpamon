package updater

import (
	"errors"
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

var restartDefaults = []mgr.RecoveryAction{{Type: mgr.ServiceRestart}}

// fakeRecovery is a recoveryConfigurer whose RecoveryActions() returns each
// queued result in turn (initial query, then the post-heal re-query).
type fakeRecovery struct {
	queries   [][]mgr.RecoveryAction
	queryErrs []error
	queryIdx  int
	setErr    error
	setCalled bool
	setReset  uint32
}

func (f *fakeRecovery) RecoveryActions() ([]mgr.RecoveryAction, error) {
	i := f.queryIdx
	f.queryIdx++
	if i < len(f.queryErrs) && f.queryErrs[i] != nil {
		return nil, f.queryErrs[i]
	}
	if i < len(f.queries) {
		return f.queries[i], nil
	}
	return nil, nil
}

func (f *fakeRecovery) SetRecoveryActions(actions []mgr.RecoveryAction, resetPeriod uint32) error {
	f.setCalled = true
	f.setReset = resetPeriod
	return f.setErr
}

func TestEnsureRecoveryRestart(t *testing.T) {
	noAction := []mgr.RecoveryAction{{Type: mgr.NoAction}}
	tests := []struct {
		name      string
		fake      fakeRecovery
		wantErr   bool
		wantSet   bool
		wantReset uint32
	}{
		{
			name:    "first action already restarts: pass without healing",
			fake:    fakeRecovery{queries: [][]mgr.RecoveryAction{restartDefaults}},
			wantErr: false,
			wantSet: false,
		},
		{
			name:      "missing: heal then re-query confirms restart",
			fake:      fakeRecovery{queries: [][]mgr.RecoveryAction{noAction, restartDefaults}},
			wantErr:   false,
			wantSet:   true,
			wantReset: recoveryResetSeconds,
		},
		{
			name:    "missing: SetRecoveryActions fails aborts",
			fake:    fakeRecovery{queries: [][]mgr.RecoveryAction{noAction}, setErr: errors.New("access denied")},
			wantErr: true,
			wantSet: true,
		},
		{
			name:    "missing: re-query still not restart aborts",
			fake:    fakeRecovery{queries: [][]mgr.RecoveryAction{noAction, noAction}},
			wantErr: true,
			wantSet: true,
		},
		{
			name:    "missing: re-query errors aborts",
			fake:    fakeRecovery{queries: [][]mgr.RecoveryAction{noAction}, queryErrs: []error{nil, errors.New("query failed")}},
			wantErr: true,
			wantSet: true,
		},
		{
			name:    "initial query errors aborts before healing",
			fake:    fakeRecovery{queryErrs: []error{errors.New("query failed")}},
			wantErr: true,
			wantSet: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.fake
			err := ensureRecoveryRestart(&f)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ensureRecoveryRestart() error = %v, wantErr %v", err, tt.wantErr)
			}
			if f.setCalled != tt.wantSet {
				t.Errorf("SetRecoveryActions called = %v, want %v", f.setCalled, tt.wantSet)
			}
			if tt.wantReset != 0 && f.setReset != tt.wantReset {
				t.Errorf("SetRecoveryActions reset = %d, want %d", f.setReset, tt.wantReset)
			}
		})
	}
}
