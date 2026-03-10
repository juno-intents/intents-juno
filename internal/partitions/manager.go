// Package partitions manages PostgreSQL range-partitioned tables.
//
// It creates daily partitions ahead of time and removes old partitions
// beyond a configurable retention window. Partition naming follows the
// convention {table}_y{YYYY}_m{MM}_d{DD}.
package partitions

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"time"
)

// DB is the minimal database interface used by Manager.
// Both *pgxpool.Pool (via a thin adapter) and test fakes satisfy this.
type DB interface {
	ExecContext(ctx context.Context, sql string, args ...any) error
	QueryContext(ctx context.Context, sql string, args ...any) (Rows, error)
}

// Rows is a minimal row-iterator interface.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
	Err() error
}

// TableConfig describes a partitioned table.
type TableConfig struct {
	TableName     string // e.g. "proof_events"
	PartitionKey  string // e.g. "created_at"
	LookaheadDays int    // create partitions N days ahead (default 7)
	RetentionDays int    // drop partitions older than N days (0 = keep forever)
}

// Manager creates and cleans up daily range partitions.
type Manager struct {
	db  DB
	log *slog.Logger
}

// NewManager returns a Manager. A nil logger is safe (logging is skipped).
func NewManager(db DB, log *slog.Logger) *Manager {
	return &Manager{db: db, log: log}
}

// EnsurePartitions creates daily partitions from today through
// today + cfg.LookaheadDays. Each partition covers
// [day 00:00:00 UTC, next_day 00:00:00 UTC).
// The SQL uses CREATE TABLE IF NOT EXISTS so the call is idempotent.
func (m *Manager) EnsurePartitions(ctx context.Context, cfg TableConfig, now time.Time) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if m.db == nil {
		return fmt.Errorf("partitions: nil database")
	}

	lookahead := cfg.LookaheadDays
	if lookahead <= 0 {
		lookahead = 7
	}

	today := truncateDay(now)
	for i := 0; i <= lookahead; i++ {
		day := today.AddDate(0, 0, i)
		next := day.AddDate(0, 0, 1)
		name := partitionName(cfg.TableName, day)

		sql := fmt.Sprintf(
			"CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')",
			name,
			cfg.TableName,
			day.Format("2006-01-02"),
			next.Format("2006-01-02"),
		)

		if err := m.db.ExecContext(ctx, sql); err != nil {
			return fmt.Errorf("partitions: create partition %s: %w", name, err)
		}
		if m.log != nil {
			m.log.Info("ensured partition", "table", cfg.TableName, "partition", name)
		}
	}
	return nil
}

// CleanupPartitions drops partitions whose date is entirely before
// now - RetentionDays. If RetentionDays is 0, nothing is dropped.
// The default partition is never dropped.
func (m *Manager) CleanupPartitions(ctx context.Context, cfg TableConfig, now time.Time) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if cfg.RetentionDays <= 0 {
		return nil
	}
	if m.db == nil {
		return fmt.Errorf("partitions: nil database")
	}

	cutoff := truncateDay(now).AddDate(0, 0, -cfg.RetentionDays)

	// List all child partitions of the table.
	rows, err := m.db.QueryContext(ctx,
		`SELECT c.relname
		 FROM pg_inherits i
		 JOIN pg_class c ON c.oid = i.inhrelid
		 JOIN pg_class p ON p.oid = i.inhparent
		 WHERE p.relname = $1
		 ORDER BY c.relname`,
		cfg.TableName,
	)
	if err != nil {
		return fmt.Errorf("partitions: list partitions for %s: %w", cfg.TableName, err)
	}
	defer rows.Close()

	var toDrop []string
	for rows.Next() {
		var relname string
		if err := rows.Scan(&relname); err != nil {
			return fmt.Errorf("partitions: scan partition name: %w", err)
		}

		day, ok := parsePartitionDate(cfg.TableName, relname)
		if !ok {
			continue // skip default or unrecognised partitions
		}
		// The partition covers [day, day+1). It is entirely before cutoff
		// when day+1 <= cutoff, i.e. the next day is at or before cutoff.
		if day.AddDate(0, 0, 1).After(cutoff) {
			continue
		}

		toDrop = append(toDrop, relname)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("partitions: iterate partitions: %w", err)
	}

	for _, name := range toDrop {
		sql := fmt.Sprintf("DROP TABLE %s", name)
		if err := m.db.ExecContext(ctx, sql); err != nil {
			return fmt.Errorf("partitions: drop partition %s: %w", name, err)
		}
		if m.log != nil {
			m.log.Info("dropped partition", "table", cfg.TableName, "partition", name)
		}
	}
	return nil
}

// partitionName returns the daily partition name for a given table and day.
func partitionName(table string, day time.Time) string {
	return fmt.Sprintf("%s_y%04d_m%02d_d%02d",
		table, day.Year(), day.Month(), day.Day())
}

// partitionDateRe matches the suffix _yYYYY_mMM_dDD.
var partitionDateRe = regexp.MustCompile(`^(.+)_y(\d{4})_m(\d{2})_d(\d{2})$`)
var tableNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// parsePartitionDate extracts the date from a partition name.
// Returns false for default partitions or names that don't match
// the expected pattern for the given table.
func parsePartitionDate(table, relname string) (time.Time, bool) {
	m := partitionDateRe.FindStringSubmatch(relname)
	if m == nil {
		return time.Time{}, false
	}
	if m[1] != table {
		return time.Time{}, false
	}

	year, _ := strconv.Atoi(m[2])
	month, _ := strconv.Atoi(m[3])
	day, _ := strconv.Atoi(m[4])

	if month < 1 || month > 12 || day < 1 || day > 31 {
		return time.Time{}, false
	}

	t := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	// Validate the parsed date is self-consistent (e.g. Feb 30 would normalise)
	if t.Year() != year || t.Month() != time.Month(month) || t.Day() != day {
		return time.Time{}, false
	}

	return t, true
}

func truncateDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func validateConfig(cfg TableConfig) error {
	if cfg.TableName == "" {
		return fmt.Errorf("partitions: empty table name")
	}
	if !tableNameRe.MatchString(cfg.TableName) {
		return fmt.Errorf("partitions: invalid table name %q", cfg.TableName)
	}
	if cfg.PartitionKey == "" {
		return fmt.Errorf("partitions: empty partition key")
	}
	return nil
}
