package alerts

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store provides persistence operations for alerts.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new alert store backed by the given connection pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// EnsureSchema creates the backoffice_alerts table and indexes if they do not exist.
func (s *Store) EnsureSchema(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, schemaSQL)
	return err
}

// InsertAlert inserts a new alert and returns its generated ID.
// Callers should check for duplicates (active alerts with the same ruleID)
// before calling this method.
func (s *Store) InsertAlert(ctx context.Context, a Alert) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO backoffice_alerts (rule_id, severity, title, detail, fired_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		a.RuleID, string(a.Severity), a.Title, a.Detail, a.FiredAt,
	).Scan(&id)
	return id, err
}

// ResolveAlert sets resolved_at on all unresolved alerts matching the given ruleID.
func (s *Store) ResolveAlert(ctx context.Context, ruleID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE backoffice_alerts
		SET resolved_at = $1
		WHERE rule_id = $2 AND resolved_at IS NULL`,
		time.Now().UTC(), ruleID,
	)
	return err
}

// AcknowledgeAlert marks a single alert as acknowledged.
func (s *Store) AcknowledgeAlert(ctx context.Context, id int64, by string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE backoffice_alerts
		SET acknowledged_at = $1, acknowledged_by = $2
		WHERE id = $3`,
		time.Now().UTC(), by, id,
	)
	return err
}

// HasActiveAlert returns true if there is at least one unresolved alert with the given ruleID.
func (s *Store) HasActiveAlert(ctx context.Context, ruleID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM backoffice_alerts
			WHERE rule_id = $1 AND resolved_at IS NULL
		)`, ruleID,
	).Scan(&exists)
	return exists, err
}

// ListActive returns all unresolved alerts ordered by fired_at descending.
func (s *Store) ListActive(ctx context.Context) ([]Alert, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, rule_id, severity, title, COALESCE(detail,''),
		       fired_at, resolved_at, acknowledged_at, COALESCE(acknowledged_by,'')
		FROM backoffice_alerts
		WHERE resolved_at IS NULL
		ORDER BY fired_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(
			&a.ID, &a.RuleID, &a.Severity, &a.Title, &a.Detail,
			&a.FiredAt, &a.ResolvedAt, &a.AcknowledgedAt, &a.AcknowledgedBy,
		); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// ListHistory returns alerts ordered by fired_at descending with pagination.
func (s *Store) ListHistory(ctx context.Context, limit, offset int) ([]Alert, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, rule_id, severity, title, COALESCE(detail,''),
		       fired_at, resolved_at, acknowledged_at, COALESCE(acknowledged_by,'')
		FROM backoffice_alerts
		ORDER BY fired_at DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(
			&a.ID, &a.RuleID, &a.Severity, &a.Title, &a.Detail,
			&a.FiredAt, &a.ResolvedAt, &a.AcknowledgedAt, &a.AcknowledgedBy,
		); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// CountActive returns the number of unresolved alerts.
func (s *Store) CountActive(ctx context.Context) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM backoffice_alerts WHERE resolved_at IS NULL`,
	).Scan(&count)
	return count, err
}
