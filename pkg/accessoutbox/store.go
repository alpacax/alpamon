// Package accessoutbox defines the storage the access event outbox in
// pkg/runner holds its events in. It imports no generated code, so modules
// that import pkg/runner build from the module zip alone; pkg/db implements it.
package accessoutbox

import (
	"context"
	"time"
)

// Row is one held access event. Times are UTC.
type Row struct {
	// ID is the event's own id, which the server deduplicates on.
	ID string
	// Payload is the JSON body as captured, without held_seconds.
	Payload       []byte
	CreatedAt     time.Time
	Attempts      int
	NextAttemptAt time.Time
}

// Store holds the outbox's rows. Errors are returned as the database reported
// them, so the caller can recognise a locked database and retry.
type Store interface {
	// Insert adds rows with zero attempts in one transaction, while the table
	// holds fewer than maxRows, counted inside that transaction; the rest are
	// refused. A row whose ID is already held is skipped.
	Insert(ctx context.Context, rows []Row, maxRows int) (stored, refused int, err error)
	// Any reports whether any row is held.
	Any(ctx context.Context) (bool, error)
	// Due returns up to limit rows whose NextAttemptAt is at or before now or
	// after skewed, ordered by CreatedAt and then ID.
	Due(ctx context.Context, now, skewed time.Time, limit int) ([]Row, error)
	// EarliestAttempt returns the earliest NextAttemptAt; ok is false when no
	// row is held.
	EarliestAttempt(ctx context.Context) (at time.Time, ok bool, err error)
	// Reschedule sets a row's attempts and next attempt time. A row that is
	// gone is not an error.
	Reschedule(ctx context.Context, id string, attempts int, next time.Time) error
	// Remove deletes a row. A row that is gone is not an error.
	Remove(ctx context.Context, id string) error
	// ReleaseAfter moves every NextAttemptAt later than at to at.
	ReleaseAfter(ctx context.Context, at time.Time) error
	// RemoveCreatedBefore deletes the rows created before cutoff and returns
	// how many it deleted.
	RemoveCreatedBefore(ctx context.Context, cutoff time.Time) (int, error)
	// CountCreatedBefore counts the rows created before cutoff.
	CountCreatedBefore(ctx context.Context, cutoff time.Time) (int, error)
}
