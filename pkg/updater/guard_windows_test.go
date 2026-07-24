package updater

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/svcdef"
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
		{"register's own delay is accepted", []mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: svcdef.RecoveryRestartDelay},
		}, true},
		{"delay exactly at the bound", []mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: maxAcceptableRestartDelay},
		}, true},
		{"delay past the bound is no guarantee", []mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: maxAcceptableRestartDelay + time.Second},
		}, false},
		{"restart six hours out leaves the server unreachable", []mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: 6 * time.Hour},
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

func TestDescribeActions(t *testing.T) {
	got := describeActions([]mgr.RecoveryAction{
		{Type: mgr.RunCommand, Delay: 0},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ComputerReboot, Delay: time.Minute},
		{Type: mgr.NoAction},
		{Type: 99},
	})
	want := []string{
		"run-command after 0s",
		"restart after 5s",
		"reboot after 1m0s",
		"none after 0s",
		"unknown(99) after 0s",
	}
	if !slices.Equal(got, want) {
		t.Errorf("describeActions() = %v, want %v", got, want)
	}
}

var restartDefaults = []mgr.RecoveryAction{{Type: mgr.ServiceRestart}}

// fakeRecovery is a recoveryConfigurer whose RecoveryActions() returns each
// queued result in turn (initial query, then the post-heal re-query).
type fakeRecovery struct {
	queries    [][]mgr.RecoveryAction
	queryErrs  []error
	queryIdx   int
	setErr     error
	setCalled  bool
	setActions []mgr.RecoveryAction
	setReset   uint32
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
	f.setActions = actions
	f.setReset = resetPeriod
	return f.setErr
}

func TestEnsureRecoveryRestart(t *testing.T) {
	noAction := []mgr.RecoveryAction{{Type: mgr.NoAction}}
	tests := []struct {
		name    string
		fake    fakeRecovery
		wantErr bool
		wantSet bool
	}{
		{
			name:    "first action already restarts: pass without healing",
			fake:    fakeRecovery{queries: [][]mgr.RecoveryAction{restartDefaults}},
			wantErr: false,
			wantSet: false,
		},
		{
			name:    "missing: heal then re-query confirms restart",
			fake:    fakeRecovery{queries: [][]mgr.RecoveryAction{noAction, restartDefaults}},
			wantErr: false,
			wantSet: true,
		},
		{
			name: "restart delayed past the bound heals like a missing restart",
			fake: fakeRecovery{queries: [][]mgr.RecoveryAction{
				{{Type: mgr.ServiceRestart, Delay: 6 * time.Hour}},
				restartDefaults,
			}},
			wantErr: false,
			wantSet: true,
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
			if !tt.wantSet {
				return
			}
			// A heal must write register's defaults verbatim—the guard's actual output.
			// Without this, a regression to NoAction or a dropped Delay passes every case.
			if want := svcdef.DefaultRecoveryActions(); !slices.Equal(f.setActions, want) {
				t.Errorf("SetRecoveryActions actions = %v, want %v", f.setActions, want)
			}
			if f.setReset != svcdef.RecoveryResetSeconds {
				t.Errorf("SetRecoveryActions reset = %d, want %d", f.setReset, svcdef.RecoveryResetSeconds)
			}
		})
	}
}
