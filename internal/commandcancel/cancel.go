// Package commandcancel carries an explicit server cancellation through command handlers.
package commandcancel

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"
)

const GracePeriod = 5 * time.Second

var ErrCancelled = errors.New("command cancelled by server")

type contextKey struct{}

type State struct {
	mu        sync.Mutex
	cancel    context.CancelCauseFunc
	cancelled bool
	finished  bool
	survivors []int
}

func NewContext(parent context.Context) (context.Context, *State) {
	ctx, cancel := context.WithCancelCause(parent)
	state := &State{cancel: cancel}
	return context.WithValue(ctx, contextKey{}, state), state
}

func FromContext(ctx context.Context) *State {
	state, _ := ctx.Value(contextKey{}).(*State)
	return state
}

func (s *State) Cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.finished {
		s.cancelled = true
		s.cancel(ErrCancelled)
	}
}

func (s *State) Finish() (bool, []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finished = true
	s.cancel(context.Canceled)
	return s.cancelled, slices.Clone(s.survivors)
}

func (s *State) AddSurvivors(pids []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.survivors = append(s.survivors, pids...)
	slices.Sort(s.survivors)
	s.survivors = slices.Compact(s.survivors)
}
