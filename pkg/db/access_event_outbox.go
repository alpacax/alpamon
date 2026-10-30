package db

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/accessoutbox"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/accesseventoutbox"
)

// AccessEventOutboxStore is the accessoutbox.Store on the agent's database.
type AccessEventOutboxStore struct {
	client *ent.Client
}

var _ accessoutbox.Store = (*AccessEventOutboxStore)(nil)

// NewAccessEventOutboxStore returns the outbox store on client.
func NewAccessEventOutboxStore(client *ent.Client) *AccessEventOutboxStore {
	return &AccessEventOutboxStore{client: client}
}

// Insert implements accessoutbox.Store.
func (s *AccessEventOutboxStore) Insert(
	ctx context.Context, rows []accessoutbox.Row, maxRows int,
) (stored, refused int, err error) {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	count, err := tx.AccessEventOutbox.Query().Count(ctx)
	if err != nil {
		return 0, 0, err
	}
	for _, row := range rows {
		if count >= maxRows {
			refused++
			continue
		}
		insertErr := tx.AccessEventOutbox.Create().
			SetID(row.ID).
			SetPayload(row.Payload).
			SetCreatedAt(row.CreatedAt).
			SetNextAttemptAt(row.NextAttemptAt).
			Exec(ctx)
		if ent.IsConstraintError(insertErr) {
			continue
		}
		if insertErr != nil {
			return 0, 0, insertErr
		}
		count++
		stored++
	}
	if err = tx.Commit(); err != nil {
		return 0, 0, err
	}
	return stored, refused, nil
}

// Any implements accessoutbox.Store.
func (s *AccessEventOutboxStore) Any(ctx context.Context) (bool, error) {
	return s.client.AccessEventOutbox.Query().Exist(ctx)
}

// Due implements accessoutbox.Store.
func (s *AccessEventOutboxStore) Due(
	ctx context.Context, now, skewed time.Time, limit int,
) ([]accessoutbox.Row, error) {
	found, err := s.client.AccessEventOutbox.Query().
		Where(accesseventoutbox.Or(
			accesseventoutbox.NextAttemptAtLTE(now),
			accesseventoutbox.NextAttemptAtGT(skewed),
		)).
		Order(ent.Asc(accesseventoutbox.FieldCreatedAt), ent.Asc(accesseventoutbox.FieldID)).
		Limit(limit).
		All(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]accessoutbox.Row, len(found))
	for i, r := range found {
		rows[i] = accessoutbox.Row{
			ID:            r.ID,
			Payload:       r.Payload,
			CreatedAt:     r.CreatedAt,
			Attempts:      r.Attempts,
			NextAttemptAt: r.NextAttemptAt,
		}
	}
	return rows, nil
}

// EarliestAttempt implements accessoutbox.Store.
func (s *AccessEventOutboxStore) EarliestAttempt(ctx context.Context) (time.Time, bool, error) {
	next, err := s.client.AccessEventOutbox.Query().
		Order(ent.Asc(accesseventoutbox.FieldNextAttemptAt)).
		First(ctx)
	if ent.IsNotFound(err) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return next.NextAttemptAt, true, nil
}

// Reschedule implements accessoutbox.Store.
func (s *AccessEventOutboxStore) Reschedule(
	ctx context.Context, id string, attempts int, next time.Time,
) error {
	err := s.client.AccessEventOutbox.UpdateOneID(id).
		SetAttempts(attempts).
		SetNextAttemptAt(next).
		Exec(ctx)
	if ent.IsNotFound(err) {
		return nil
	}
	return err
}

// Remove implements accessoutbox.Store.
func (s *AccessEventOutboxStore) Remove(ctx context.Context, id string) error {
	err := s.client.AccessEventOutbox.DeleteOneID(id).Exec(ctx)
	if ent.IsNotFound(err) {
		return nil
	}
	return err
}

// ReleaseAfter implements accessoutbox.Store.
func (s *AccessEventOutboxStore) ReleaseAfter(ctx context.Context, at time.Time) error {
	return s.client.AccessEventOutbox.Update().
		Where(accesseventoutbox.NextAttemptAtGT(at)).
		SetNextAttemptAt(at).
		Exec(ctx)
}

// RemoveCreatedBefore implements accessoutbox.Store.
func (s *AccessEventOutboxStore) RemoveCreatedBefore(
	ctx context.Context, cutoff time.Time,
) (int, error) {
	return s.client.AccessEventOutbox.Delete().
		Where(accesseventoutbox.CreatedAtLT(cutoff)).
		Exec(ctx)
}

// CountCreatedBefore implements accessoutbox.Store.
func (s *AccessEventOutboxStore) CountCreatedBefore(
	ctx context.Context, cutoff time.Time,
) (int, error) {
	return s.client.AccessEventOutbox.Query().
		Where(accesseventoutbox.CreatedAtLT(cutoff)).
		Count(ctx)
}
