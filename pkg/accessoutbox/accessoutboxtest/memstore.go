// Package accessoutboxtest provides an in-memory accessoutbox.Store and the
// contract every Store must meet, so tests outside pkg/db need no database.
package accessoutboxtest

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/accessoutbox"
)

// ErrLocked is what SQLite reports while another writer holds its lock.
var ErrLocked = errors.New("database is locked (5) (SQLITE_BUSY)")

// Op names a Store method, for MemStore.FailOn.
type Op string

const (
	OpInsert              Op = "Insert"
	OpAny                 Op = "Any"
	OpDue                 Op = "Due"
	OpEarliestAttempt     Op = "EarliestAttempt"
	OpReschedule          Op = "Reschedule"
	OpRemove              Op = "Remove"
	OpReleaseAfter        Op = "ReleaseAfter"
	OpRemoveCreatedBefore Op = "RemoveCreatedBefore"
	OpCountCreatedBefore  Op = "CountCreatedBefore"
)

// MemStore is an accessoutbox.Store held in memory. It outlives the outbox
// that uses it, so a second outbox on the same MemStore sees a restart.
type MemStore struct {
	mu   sync.Mutex
	rows map[string]accessoutbox.Row
	// failOn, when set, runs before each method; a non-nil error fails the call unchanged.
	failOn func(Op) error
}

var _ accessoutbox.Store = (*MemStore)(nil)

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{rows: map[string]accessoutbox.Row{}}
}

// FailOn makes each call return fail(op) when that is not nil; nil clears it.
func (s *MemStore) FailOn(fail func(Op) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failOn = fail
}

// Seed stores row as given, attempts included, past any bound.
func (s *MemStore) Seed(row accessoutbox.Row) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[row.ID] = clone(row)
}

// Rows returns every held row ordered by CreatedAt and then ID.
func (s *MemStore) Rows() []accessoutbox.Row {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sortedLocked()
}

func (s *MemStore) fail(op Op) error {
	if s.failOn == nil {
		return nil
	}
	return s.failOn(op)
}

func (s *MemStore) sortedLocked() []accessoutbox.Row {
	rows := make([]accessoutbox.Row, 0, len(s.rows))
	for _, row := range s.rows {
		rows = append(rows, clone(row))
	}
	slices.SortFunc(rows, func(a, b accessoutbox.Row) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return rows
}

// Insert implements accessoutbox.Store.
func (s *MemStore) Insert(_ context.Context, rows []accessoutbox.Row, maxRows int) (stored, refused int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail(OpInsert); err != nil {
		return 0, 0, err
	}
	count := len(s.rows)
	for _, row := range rows {
		if count >= maxRows {
			refused++
			continue
		}
		if _, held := s.rows[row.ID]; held {
			continue
		}
		row.Attempts = 0
		s.rows[row.ID] = clone(row)
		count++
		stored++
	}
	return stored, refused, nil
}

// Any implements accessoutbox.Store.
func (s *MemStore) Any(context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail(OpAny); err != nil {
		return false, err
	}
	return len(s.rows) > 0, nil
}

// Due implements accessoutbox.Store.
func (s *MemStore) Due(_ context.Context, now, skewed time.Time, limit int) ([]accessoutbox.Row, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail(OpDue); err != nil {
		return nil, err
	}
	var due []accessoutbox.Row
	for _, row := range s.sortedLocked() {
		if len(due) == limit {
			break
		}
		if !row.NextAttemptAt.After(now) || row.NextAttemptAt.After(skewed) {
			due = append(due, row)
		}
	}
	return due, nil
}

// EarliestAttempt implements accessoutbox.Store.
func (s *MemStore) EarliestAttempt(context.Context) (time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail(OpEarliestAttempt); err != nil {
		return time.Time{}, false, err
	}
	var earliest time.Time
	held := false
	for _, row := range s.rows {
		if !held || row.NextAttemptAt.Before(earliest) {
			earliest, held = row.NextAttemptAt, true
		}
	}
	return earliest, held, nil
}

// Reschedule implements accessoutbox.Store.
func (s *MemStore) Reschedule(_ context.Context, id string, attempts int, next time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail(OpReschedule); err != nil {
		return err
	}
	row, held := s.rows[id]
	if !held {
		return nil
	}
	row.Attempts, row.NextAttemptAt = attempts, next
	s.rows[id] = row
	return nil
}

// Remove implements accessoutbox.Store.
func (s *MemStore) Remove(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail(OpRemove); err != nil {
		return err
	}
	delete(s.rows, id)
	return nil
}

// ReleaseAfter implements accessoutbox.Store.
func (s *MemStore) ReleaseAfter(_ context.Context, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail(OpReleaseAfter); err != nil {
		return err
	}
	for id, row := range s.rows {
		if row.NextAttemptAt.After(at) {
			row.NextAttemptAt = at
			s.rows[id] = row
		}
	}
	return nil
}

// RemoveCreatedBefore implements accessoutbox.Store.
func (s *MemStore) RemoveCreatedBefore(_ context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail(OpRemoveCreatedBefore); err != nil {
		return 0, err
	}
	removed := 0
	for id, row := range s.rows {
		if row.CreatedAt.Before(cutoff) {
			delete(s.rows, id)
			removed++
		}
	}
	return removed, nil
}

// CountCreatedBefore implements accessoutbox.Store.
func (s *MemStore) CountCreatedBefore(_ context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail(OpCountCreatedBefore); err != nil {
		return 0, err
	}
	count := 0
	for _, row := range s.rows {
		if row.CreatedAt.Before(cutoff) {
			count++
		}
	}
	return count, nil
}

func clone(row accessoutbox.Row) accessoutbox.Row {
	row.Payload = slices.Clone(row.Payload)
	return row
}
