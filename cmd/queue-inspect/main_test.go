package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeInspector struct {
	rows []queueStatsRow
	err  error
}

func (f fakeInspector) Inspect(ctx context.Context, topics, groups []string) ([]queueStatsRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]queueStatsRow(nil), f.rows...), nil
}

func TestParseArgsValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{name: "missing dsn", args: nil, wantErr: true},
		{name: "dsn env ok", args: []string{"--postgres-dsn-env", "QUEUE_DSN"}, wantErr: false},
		{name: "dsn ok", args: []string{"--postgres-dsn", "postgres://example"}, wantErr: false},
		{name: "bad format", args: []string{"--postgres-dsn", "postgres://example", "--format", "xml"}, wantErr: true},
		{name: "negative max backlog", args: []string{"--postgres-dsn", "postgres://example", "--max-backlog", "-2"}, wantErr: true},
		{name: "negative max expired leases", args: []string{"--postgres-dsn", "postgres://example", "--max-expired-leases", "-2"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseArgs: %v", err)
			}
		})
	}
}

func TestParseArgsFilters(t *testing.T) {
	t.Parallel()

	cfg, err := parseArgs([]string{
		"--postgres-dsn", "postgres://example",
		"--topics", "proof.requests.v1, proof.fulfillments.v1",
		"--groups", "proof-requestor, deposit-relayer",
		"--format", "json",
		"--timeout", "5s",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if got, want := strings.Join(cfg.Topics, ","), "proof.requests.v1,proof.fulfillments.v1"; got != want {
		t.Fatalf("Topics = %q, want %q", got, want)
	}
	if got, want := strings.Join(cfg.Groups, ","), "proof-requestor,deposit-relayer"; got != want {
		t.Fatalf("Groups = %q, want %q", got, want)
	}
	if cfg.Format != "json" {
		t.Fatalf("Format = %q, want json", cfg.Format)
	}
	if cfg.Timeout != 5*time.Second {
		t.Fatalf("Timeout = %s, want 5s", cfg.Timeout)
	}
}

func TestRunMainJSONOutput(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := runMainWithInspector(
		context.Background(),
		[]string{"--postgres-dsn", "postgres://example", "--format", "json"},
		&out,
		fakeInspector{rows: []queueStatsRow{{
			Topic:              "proof.requests.v1",
			ConsumerGroup:      "proof-requestor",
			FirstSeq:           1,
			LastSeq:            4,
			MessageCount:       4,
			NextSeq:            3,
			Backlog:            2,
			UnackedDeliveries:  2,
			LeasedDeliveries:   1,
			ExpiredLeases:      0,
			MaxAttemptCount:    2,
			LastMessageAgeSecs: 7,
		}}},
	)
	if err != nil {
		t.Fatalf("runMainWithInspector: %v", err)
	}
	var report inspectReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("json output: %v\n%s", err, out.String())
	}
	if len(report.Rows) != 1 {
		t.Fatalf("row count = %d, want 1", len(report.Rows))
	}
	if got, want := report.Rows[0].Backlog, int64(2); got != want {
		t.Fatalf("Backlog = %d, want %d", got, want)
	}
	if got, want := report.TotalBacklog, int64(2); got != want {
		t.Fatalf("TotalBacklog = %d, want %d", got, want)
	}
}

func TestRunMainTextOutput(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := runMainWithInspector(
		context.Background(),
		[]string{"--postgres-dsn", "postgres://example"},
		&out,
		fakeInspector{rows: []queueStatsRow{{
			Topic:         "proof.requests.v1",
			ConsumerGroup: "proof-requestor",
			LastSeq:       4,
			NextSeq:       5,
			MessageCount:  4,
			Backlog:       0,
		}}},
	)
	if err != nil {
		t.Fatalf("runMainWithInspector: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "proof.requests.v1") || !strings.Contains(got, "proof-requestor") || !strings.Contains(got, "backlog=0") {
		t.Fatalf("unexpected text output: %q", got)
	}
}

func TestRunMainThresholdFailures(t *testing.T) {
	t.Parallel()

	rows := []queueStatsRow{{
		Topic:         "proof.requests.v1",
		ConsumerGroup: "proof-requestor",
		Backlog:       5,
		ExpiredLeases: 2,
	}}
	tests := []struct {
		name string
		args []string
	}{
		{name: "backlog", args: []string{"--postgres-dsn", "postgres://example", "--max-backlog", "4"}},
		{name: "expired leases", args: []string{"--postgres-dsn", "postgres://example", "--max-expired-leases", "1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			err := runMainWithInspector(context.Background(), tt.args, &out, fakeInspector{rows: rows})
			if err == nil {
				t.Fatal("expected threshold error")
			}
			if got := out.String(); !strings.Contains(got, "proof.requests.v1") || !strings.Contains(got, "backlog=5") {
				t.Fatalf("expected diagnostic report on threshold failure, got %q", got)
			}
		})
	}
}

func TestRunMainPropagatesInspectorError(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := runMainWithInspector(
		context.Background(),
		[]string{"--postgres-dsn", "postgres://example"},
		&out,
		fakeInspector{err: errors.New("database down")},
	)
	if err == nil || !strings.Contains(err.Error(), "database down") {
		t.Fatalf("expected inspector error, got %v", err)
	}
}
