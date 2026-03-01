package partitions

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// fakeDB records SQL statements for verification without requiring a real database.
type fakeDB struct {
	execCalls  []execCall
	queryCalls []queryCall
	queryRows  []fakeRow
	execErr    error
	queryErr   error
}

type execCall struct {
	sql  string
	args []any
}

type queryCall struct {
	sql  string
	args []any
}

type fakeRow struct {
	relname string
}

func (f *fakeDB) ExecContext(ctx context.Context, sql string, args ...any) error {
	f.execCalls = append(f.execCalls, execCall{sql: sql, args: args})
	return f.execErr
}

func (f *fakeDB) QueryContext(ctx context.Context, sql string, args ...any) (Rows, error) {
	f.queryCalls = append(f.queryCalls, queryCall{sql: sql, args: args})
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	return &fakeRows{rows: f.queryRows, pos: -1}, nil
}

type fakeRows struct {
	rows []fakeRow
	pos  int
}

func (r *fakeRows) Next() bool {
	r.pos++
	return r.pos < len(r.rows)
}

func (r *fakeRows) Scan(dest ...any) error {
	if r.pos >= len(r.rows) {
		return fmt.Errorf("no more rows")
	}
	if len(dest) != 1 {
		return fmt.Errorf("expected 1 scan dest, got %d", len(dest))
	}
	ptr, ok := dest[0].(*string)
	if !ok {
		return fmt.Errorf("expected *string scan dest")
	}
	*ptr = r.rows[r.pos].relname
	return nil
}

func (r *fakeRows) Close() error { return nil }
func (r *fakeRows) Err() error  { return nil }

func TestPartitionName(t *testing.T) {
	tests := []struct {
		table string
		day   time.Time
		want  string
	}{
		{"proof_events", time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), "proof_events_y2026_m03_d01"},
		{"proof_events", time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC), "proof_events_y2026_m12_d31"},
		{"deposit_jobs", time.Date(2027, 1, 5, 0, 0, 0, 0, time.UTC), "deposit_jobs_y2027_m01_d05"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := partitionName(tt.table, tt.day)
			if got != tt.want {
				t.Errorf("partitionName(%q, %v) = %q, want %q", tt.table, tt.day, got, tt.want)
			}
		})
	}
}

func TestEnsurePartitions_CreatesCorrectSQL(t *testing.T) {
	db := &fakeDB{}
	m := NewManager(db, nil)
	cfg := TableConfig{
		TableName:     "proof_events",
		PartitionKey:  "created_at",
		LookaheadDays: 3,
		RetentionDays: 0,
	}

	now := time.Date(2026, 3, 1, 15, 30, 0, 0, time.UTC)
	ctx := context.Background()
	err := m.EnsurePartitions(ctx, cfg, now)
	if err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}

	// Should create 4 partitions: today (Mar 1) + 3 days ahead (Mar 2, 3, 4)
	wantCount := 4
	if len(db.execCalls) != wantCount {
		t.Fatalf("expected %d exec calls, got %d", wantCount, len(db.execCalls))
	}

	// Verify first partition SQL
	first := db.execCalls[0]
	wantSQL := `CREATE TABLE IF NOT EXISTS proof_events_y2026_m03_d01 PARTITION OF proof_events FOR VALUES FROM ('2026-03-01') TO ('2026-03-02')`
	if first.sql != wantSQL {
		t.Errorf("first SQL:\n  got:  %s\n  want: %s", first.sql, wantSQL)
	}

	// Verify last partition
	last := db.execCalls[3]
	wantLastSQL := `CREATE TABLE IF NOT EXISTS proof_events_y2026_m03_d04 PARTITION OF proof_events FOR VALUES FROM ('2026-03-04') TO ('2026-03-05')`
	if last.sql != wantLastSQL {
		t.Errorf("last SQL:\n  got:  %s\n  want: %s", last.sql, wantLastSQL)
	}
}

func TestEnsurePartitions_Idempotent(t *testing.T) {
	db := &fakeDB{}
	m := NewManager(db, nil)
	cfg := TableConfig{
		TableName:     "proof_events",
		PartitionKey:  "created_at",
		LookaheadDays: 2,
	}

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	ctx := context.Background()

	// First run
	if err := m.EnsurePartitions(ctx, cfg, now); err != nil {
		t.Fatalf("first EnsurePartitions: %v", err)
	}
	firstCount := len(db.execCalls)

	// Second run should produce the same calls (CREATE TABLE IF NOT EXISTS is idempotent)
	if err := m.EnsurePartitions(ctx, cfg, now); err != nil {
		t.Fatalf("second EnsurePartitions: %v", err)
	}
	secondCount := len(db.execCalls) - firstCount
	if secondCount != firstCount {
		t.Errorf("idempotent run: expected %d calls, got %d", firstCount, secondCount)
	}
}

func TestEnsurePartitions_ExecError(t *testing.T) {
	db := &fakeDB{
		execErr: fmt.Errorf("connection refused"),
	}
	m := NewManager(db, nil)
	cfg := TableConfig{
		TableName:     "proof_events",
		PartitionKey:  "created_at",
		LookaheadDays: 1,
	}

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	err := m.EnsurePartitions(context.Background(), cfg, now)
	if err == nil {
		t.Fatal("expected error from EnsurePartitions")
	}
}

func TestEnsurePartitions_DefaultLookahead(t *testing.T) {
	db := &fakeDB{}
	m := NewManager(db, nil)
	cfg := TableConfig{
		TableName:     "proof_events",
		PartitionKey:  "created_at",
		LookaheadDays: 0, // should use default of 7
	}

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if err := m.EnsurePartitions(context.Background(), cfg, now); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}

	// today + 7 days = 8 partitions
	wantCount := 8
	if len(db.execCalls) != wantCount {
		t.Errorf("default lookahead: expected %d exec calls, got %d", wantCount, len(db.execCalls))
	}
}

func TestEnsurePartitions_InvalidConfig(t *testing.T) {
	db := &fakeDB{}
	m := NewManager(db, nil)

	tests := []struct {
		name string
		cfg  TableConfig
	}{
		{"empty table name", TableConfig{PartitionKey: "created_at"}},
		{"empty partition key", TableConfig{TableName: "proof_events"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.EnsurePartitions(context.Background(), tt.cfg, time.Now())
			if err == nil {
				t.Error("expected error for invalid config")
			}
		})
	}
}

func TestCleanupPartitions_DropsOldPartitions(t *testing.T) {
	// Simulate existing partitions: some old, some current
	db := &fakeDB{
		queryRows: []fakeRow{
			{relname: "proof_events_y2026_m02_d01"}, // old, should be dropped
			{relname: "proof_events_y2026_m02_d15"}, // old, should be dropped
			{relname: "proof_events_y2026_m02_d28"}, // recent, keep (within 7 day retention from Mar 1)
			{relname: "proof_events_y2026_m03_d01"}, // current, keep
			{relname: "proof_events_default"},        // default partition, never drop
		},
	}
	m := NewManager(db, nil)
	cfg := TableConfig{
		TableName:     "proof_events",
		PartitionKey:  "created_at",
		RetentionDays: 7,
	}

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	err := m.CleanupPartitions(context.Background(), cfg, now)
	if err == nil {
		// The query should have been called to list partitions
		if len(db.queryCalls) == 0 {
			t.Fatal("expected at least one query call to list partitions")
		}
	}

	// Should have dropped 2 old partitions
	dropCount := 0
	for _, c := range db.execCalls {
		if len(c.sql) > 10 && c.sql[:10] == "DROP TABLE" {
			dropCount++
		}
	}
	if dropCount != 2 {
		t.Errorf("expected 2 DROP TABLE calls, got %d", dropCount)
	}

	// Verify the dropped tables are the correct ones
	var droppedTables []string
	for _, c := range db.execCalls {
		if len(c.sql) > 10 && c.sql[:10] == "DROP TABLE" {
			droppedTables = append(droppedTables, c.sql)
		}
	}
	wantDropped := []string{
		"DROP TABLE proof_events_y2026_m02_d01",
		"DROP TABLE proof_events_y2026_m02_d15",
	}
	if len(droppedTables) != len(wantDropped) {
		t.Fatalf("dropped tables count mismatch: got %d, want %d", len(droppedTables), len(wantDropped))
	}
	for i, got := range droppedTables {
		if got != wantDropped[i] {
			t.Errorf("dropped[%d] = %q, want %q", i, got, wantDropped[i])
		}
	}
}

func TestCleanupPartitions_ZeroRetention(t *testing.T) {
	db := &fakeDB{
		queryRows: []fakeRow{
			{relname: "proof_events_y2025_m01_d01"},
		},
	}
	m := NewManager(db, nil)
	cfg := TableConfig{
		TableName:     "proof_events",
		PartitionKey:  "created_at",
		RetentionDays: 0, // keep forever
	}

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	err := m.CleanupPartitions(context.Background(), cfg, now)
	if err != nil {
		t.Fatalf("CleanupPartitions: %v", err)
	}

	// No partitions should be dropped
	for _, c := range db.execCalls {
		if len(c.sql) >= 10 && c.sql[:10] == "DROP TABLE" {
			t.Errorf("unexpected DROP TABLE with RetentionDays=0: %s", c.sql)
		}
	}
}

func TestCleanupPartitions_NoPartitionsExist(t *testing.T) {
	db := &fakeDB{
		queryRows: nil, // no partitions
	}
	m := NewManager(db, nil)
	cfg := TableConfig{
		TableName:     "proof_events",
		PartitionKey:  "created_at",
		RetentionDays: 30,
	}

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	err := m.CleanupPartitions(context.Background(), cfg, now)
	if err != nil {
		t.Fatalf("CleanupPartitions with no partitions: %v", err)
	}
	// No drops should occur
	if len(db.execCalls) != 0 {
		t.Errorf("expected 0 exec calls, got %d", len(db.execCalls))
	}
}

func TestCleanupPartitions_QueryError(t *testing.T) {
	db := &fakeDB{
		queryErr: fmt.Errorf("connection timeout"),
	}
	m := NewManager(db, nil)
	cfg := TableConfig{
		TableName:     "proof_events",
		PartitionKey:  "created_at",
		RetentionDays: 7,
	}

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	err := m.CleanupPartitions(context.Background(), cfg, now)
	if err == nil {
		t.Fatal("expected error from CleanupPartitions with query error")
	}
}

func TestCleanupPartitions_SkipsDefaultPartition(t *testing.T) {
	db := &fakeDB{
		queryRows: []fakeRow{
			{relname: "proof_events_default"},
			{relname: "proof_events_y2020_m01_d01"}, // very old, should be dropped
		},
	}
	m := NewManager(db, nil)
	cfg := TableConfig{
		TableName:     "proof_events",
		PartitionKey:  "created_at",
		RetentionDays: 7,
	}

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	err := m.CleanupPartitions(context.Background(), cfg, now)
	if err != nil {
		t.Fatalf("CleanupPartitions: %v", err)
	}

	// Should drop the old partition but not the default
	dropCount := 0
	for _, c := range db.execCalls {
		if len(c.sql) >= 10 && c.sql[:10] == "DROP TABLE" {
			dropCount++
			if c.sql == "DROP TABLE proof_events_default" {
				t.Error("should not drop default partition")
			}
		}
	}
	if dropCount != 1 {
		t.Errorf("expected 1 DROP TABLE call, got %d", dropCount)
	}
}

func TestCleanupPartitions_InvalidConfig(t *testing.T) {
	db := &fakeDB{}
	m := NewManager(db, nil)

	err := m.CleanupPartitions(context.Background(), TableConfig{}, time.Now())
	if err == nil {
		t.Error("expected error for empty table name")
	}
}

func TestParsePartitionDate(t *testing.T) {
	tests := []struct {
		name    string
		table   string
		relname string
		wantDay time.Time
		wantOK  bool
	}{
		{
			"valid",
			"proof_events",
			"proof_events_y2026_m03_d01",
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
			true,
		},
		{
			"default partition",
			"proof_events",
			"proof_events_default",
			time.Time{},
			false,
		},
		{
			"wrong prefix",
			"proof_events",
			"deposit_jobs_y2026_m03_d01",
			time.Time{},
			false,
		},
		{
			"malformed date",
			"proof_events",
			"proof_events_y2026_m13_d01",
			time.Time{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parsePartitionDate(tt.table, tt.relname)
			if ok != tt.wantOK {
				t.Errorf("parsePartitionDate(%q, %q) ok = %v, want %v", tt.table, tt.relname, ok, tt.wantOK)
			}
			if ok && !got.Equal(tt.wantDay) {
				t.Errorf("parsePartitionDate(%q, %q) = %v, want %v", tt.table, tt.relname, got, tt.wantDay)
			}
		})
	}
}

func TestNewManager_NilDB(t *testing.T) {
	m := NewManager(nil, nil)
	if m == nil {
		t.Fatal("NewManager should return non-nil even with nil db")
	}

	err := m.EnsurePartitions(context.Background(), TableConfig{
		TableName:    "proof_events",
		PartitionKey: "created_at",
	}, time.Now())
	if err == nil {
		t.Error("expected error with nil DB")
	}
}

func TestEnsurePartitions_MonthBoundary(t *testing.T) {
	db := &fakeDB{}
	m := NewManager(db, nil)
	cfg := TableConfig{
		TableName:     "proof_events",
		PartitionKey:  "created_at",
		LookaheadDays: 3,
	}

	// End of month: March 30 -> should create partitions crossing into April
	now := time.Date(2026, 3, 30, 12, 0, 0, 0, time.UTC)
	if err := m.EnsurePartitions(context.Background(), cfg, now); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}

	// Expect: Mar 30, Mar 31, Apr 1, Apr 2
	wantNames := []string{
		"proof_events_y2026_m03_d30",
		"proof_events_y2026_m03_d31",
		"proof_events_y2026_m04_d01",
		"proof_events_y2026_m04_d02",
	}
	if len(db.execCalls) != len(wantNames) {
		t.Fatalf("expected %d exec calls, got %d", len(wantNames), len(db.execCalls))
	}

	for i, call := range db.execCalls {
		expected := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s PARTITION OF proof_events", wantNames[i])
		if len(call.sql) < len(expected) || call.sql[:len(expected)] != expected {
			t.Errorf("call[%d] SQL prefix mismatch:\n  got:  %s\n  want prefix: %s", i, call.sql, expected)
		}
	}
}

func TestEnsurePartitions_YearBoundary(t *testing.T) {
	db := &fakeDB{}
	m := NewManager(db, nil)
	cfg := TableConfig{
		TableName:     "proof_events",
		PartitionKey:  "created_at",
		LookaheadDays: 2,
	}

	now := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	if err := m.EnsurePartitions(context.Background(), cfg, now); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}

	// Dec 31, Jan 1, Jan 2
	wantNames := []string{
		"proof_events_y2026_m12_d31",
		"proof_events_y2027_m01_d01",
		"proof_events_y2027_m01_d02",
	}
	if len(db.execCalls) != len(wantNames) {
		t.Fatalf("expected %d exec calls, got %d", len(wantNames), len(db.execCalls))
	}
	for i, call := range db.execCalls {
		expected := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s PARTITION OF proof_events", wantNames[i])
		if len(call.sql) < len(expected) || call.sql[:len(expected)] != expected {
			t.Errorf("call[%d] SQL prefix mismatch:\n  got:  %s\n  want prefix: %s", i, call.sql, expected)
		}
	}
}
