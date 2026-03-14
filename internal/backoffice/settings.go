package backoffice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrInvalidSettingsConfig = errors.New("backoffice: invalid settings config")

const settingsAuditSchemaSQL = `
CREATE TABLE IF NOT EXISTS backoffice_settings_audit (
	id BIGSERIAL PRIMARY KEY,
	setting_key TEXT NOT NULL,
	old_value TEXT,
	new_value TEXT NOT NULL,
	tx_hash TEXT,
	updated_by TEXT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT backoffice_settings_audit_setting_key_nonempty CHECK (setting_key <> ''),
	CONSTRAINT backoffice_settings_audit_new_value_nonempty CHECK (new_value <> ''),
	CONSTRAINT backoffice_settings_audit_updated_by_nonempty CHECK (updated_by <> '')
);

CREATE INDEX IF NOT EXISTS idx_backoffice_settings_audit_updated_at
	ON backoffice_settings_audit (updated_at DESC);
`

type MinDepositUpdater interface {
	SetMinDepositAmount(ctx context.Context, amount uint64) (common.Hash, error)
}

type SettingsAuditEntry struct {
	ID         int64
	SettingKey string
	OldValue   string
	NewValue   string
	TxHash     string
	UpdatedBy  string
	UpdatedAt  time.Time
}

type SettingsAuditStore struct {
	pool *pgxpool.Pool
}

func NewSettingsAuditStore(pool *pgxpool.Pool) (*SettingsAuditStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: nil pool", ErrInvalidSettingsConfig)
	}
	return &SettingsAuditStore{pool: pool}, nil
}

func (s *SettingsAuditStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil audit store", ErrInvalidSettingsConfig)
	}
	if _, err := s.pool.Exec(ctx, settingsAuditSchemaSQL); err != nil {
		return fmt.Errorf("backoffice: ensure settings audit schema: %w", err)
	}
	return nil
}

func (s *SettingsAuditStore) Insert(ctx context.Context, entry SettingsAuditEntry) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil audit store", ErrInvalidSettingsConfig)
	}
	entry.SettingKey = strings.TrimSpace(entry.SettingKey)
	entry.NewValue = strings.TrimSpace(entry.NewValue)
	entry.UpdatedBy = strings.TrimSpace(entry.UpdatedBy)
	entry.TxHash = strings.TrimSpace(entry.TxHash)
	if entry.SettingKey == "" || entry.NewValue == "" || entry.UpdatedBy == "" {
		return fmt.Errorf("%w: invalid audit entry", ErrInvalidSettingsConfig)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO backoffice_settings_audit (
			setting_key,
			old_value,
			new_value,
			tx_hash,
			updated_by,
			updated_at
		) VALUES ($1, $2, $3, NULLIF($4, ''), $5, now())
	`, entry.SettingKey, nullableText(entry.OldValue), entry.NewValue, entry.TxHash, entry.UpdatedBy)
	if err != nil {
		return fmt.Errorf("backoffice: insert settings audit: %w", err)
	}
	return nil
}

func (s *SettingsAuditStore) List(ctx context.Context, limit int) ([]SettingsAuditEntry, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil audit store", ErrInvalidSettingsConfig)
	}
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, setting_key, COALESCE(old_value, ''), new_value, COALESCE(tx_hash, ''), updated_by, updated_at
		FROM backoffice_settings_audit
		ORDER BY updated_at DESC, id DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("backoffice: list settings audit: %w", err)
	}
	defer rows.Close()

	out := make([]SettingsAuditEntry, 0, limit)
	for rows.Next() {
		var entry SettingsAuditEntry
		if err := rows.Scan(
			&entry.ID,
			&entry.SettingKey,
			&entry.OldValue,
			&entry.NewValue,
			&entry.TxHash,
			&entry.UpdatedBy,
			&entry.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("backoffice: scan settings audit: %w", err)
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("backoffice: iterate settings audit: %w", err)
	}
	return out, nil
}

func nullableText(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

type scanStringRow interface {
	Scan(dest ...any) error
}

func scanOptionalString(row scanStringRow) (*string, error) {
	var value *string
	if err := row.Scan(&value); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return value, nil
}
