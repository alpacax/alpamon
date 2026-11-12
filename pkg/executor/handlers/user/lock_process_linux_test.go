package user

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAccountProcess struct {
	id                               int
	frozen, killed, closed, stubborn bool
	stopErr                          error
	events                           *[]string
}

func (p *fakeAccountProcess) pid() int { return p.id }
func (p *fakeAccountProcess) stop() error {
	p.frozen = true
	if p.events != nil {
		*p.events = append(*p.events, "stop")
	}
	return p.stopErr
}
func (p *fakeAccountProcess) stopped() (bool, error) { return p.frozen, nil }
func (p *fakeAccountProcess) kill() error {
	p.killed = true
	if p.events != nil {
		*p.events = append(*p.events, "kill")
	}
	return nil
}
func (p *fakeAccountProcess) alive() (bool, error) { return !p.killed || p.stubborn, nil }
func (p *fakeAccountProcess) close()               { p.closed = true }

func TestEndAccountProcessTree(t *testing.T) {
	for _, tc := range []string{"tree", "stop failure", "session failure", "scan failure"} {
		t.Run(tc, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var events []string
				parent := &fakeAccountProcess{id: 10, events: &events}
				child := &fakeAccountProcess{id: 11, events: &events}
				if tc == "stop failure" {
					parent.stopErr = errors.New("stop failed")
				}
				calls := 0
				scan := func(_ uint64, tracked map[int]accountProcess) ([]accountProcess, error) {
					calls++
					if calls == 1 {
						return []accountProcess{parent}, nil
					}
					if calls == 2 {
						if tc == "scan failure" {
							return nil, errors.New("scan failed")
						}
						assert.True(t, parent.frozen)
						return []accountProcess{child}, nil
					}
					return nil, nil
				}
				count, err := endAccountProcesses(context.Background(), 1001, func(context.Context) error {
					assert.True(t, parent.frozen && child.frozen)
					events = append(events, "terminate-user")
					if tc == "session failure" {
						return errors.New("session failed")
					}
					return nil
				}, scan)
				assert.Equal(t, 1, count)
				if tc == "tree" {
					require.NoError(t, err)
					assert.Equal(t, []string{"stop", "stop", "terminate-user", "kill", "kill"}, events)
				} else {
					require.Error(t, err)
				}
				assert.True(t, parent.killed && parent.closed)
				if calls >= 3 {
					assert.True(t, child.killed && child.closed)
				}
			})
		})
	}
}

func TestProcessIdentityMatching(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		want         bool
	}{
		{"real uid", "Uid:\t1001 0 0 0\nState:\tS\nPPid:\t1\n", true},
		{"effective uid", "Uid:\t0 1001 0 0\nState:\tS\nPPid:\t1\n", false},
		{"saved uid", "Uid:\t0 0 1001 0\nPPid:\t1\n", true},
		{"filesystem uid", "Uid:\t0 0 0 1001\nPPid:\t1\n", false},
		{"descendant", "Uid:\t0 0 0 0\nState:\tS\nPPid:\t10\n", true},
		{"unrelated", "Uid:\t0 0 0 0\nState:\tS\nPPid:\t1\n", false},
		{"zombie leader with live threads", "Uid:\t1001 1001 1001 1001\nState:\tZ\nPPid:\t1\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, matchesAccountProcess(tc.status, 1001, map[int]accountProcess{10: &fakeAccountProcess{id: 10}}))
		})
	}
}

func TestStopFailureClosesAllHandles(t *testing.T) {
	first := &fakeAccountProcess{id: 10, stopErr: errors.New("stop failed")}
	second := &fakeAccountProcess{id: 11}
	_, err := endAccountProcesses(context.Background(), 1001, nil, func(uint64, map[int]accountProcess) ([]accountProcess, error) {
		return []accountProcess{first, second}, nil
	})
	require.ErrorContains(t, err, "stop failed")
	assert.True(t, first.closed)
	assert.True(t, second.closed)
}
