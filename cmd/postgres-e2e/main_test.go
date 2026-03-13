package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakePostgresRunner struct {
	queryResult []string
	queryErr    error
	execErr     error

	gotDSN   string
	gotSQL   string
	queryHit int
	execHit  int
}

func (f *fakePostgresRunner) Query(_ context.Context, dsn, sql string) ([]string, error) {
	f.gotDSN = dsn
	f.gotSQL = sql
	f.queryHit++
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	return append([]string(nil), f.queryResult...), nil
}

func (f *fakePostgresRunner) Exec(_ context.Context, dsn, sql string) error {
	f.gotDSN = dsn
	f.gotSQL = sql
	f.execHit++
	return f.execErr
}

func TestParseArgsRequiresExactlyOneMode(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--postgres-dsn", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
	})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("parseArgs() error = %v, want exactly one mode error", err)
	}

	query := base64.StdEncoding.EncodeToString([]byte("SELECT 1"))
	execStmt := base64.StdEncoding.EncodeToString([]byte("DELETE FROM foo"))
	_, err = parseArgs([]string{
		"--postgres-dsn", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
		"--query-base64", query,
		"--exec-base64", execStmt,
	})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("parseArgs() error = %v, want exactly one mode error", err)
	}
}

func TestParseArgsValidQuery(t *testing.T) {
	t.Parallel()

	query := base64.StdEncoding.EncodeToString([]byte("SELECT 1"))
	cfg, err := parseArgs([]string{
		"--postgres-dsn", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
		"--query-base64", query,
		"--timeout", "45s",
		"--output", "/tmp/postgres-e2e.out",
	})
	if err != nil {
		t.Fatalf("parseArgs() error = %v", err)
	}
	if cfg.PostgresDSN == "" {
		t.Fatalf("expected postgres dsn")
	}
	if cfg.QueryBase64 != query {
		t.Fatalf("query base64 mismatch: got %q want %q", cfg.QueryBase64, query)
	}
	if cfg.Timeout != 45*time.Second {
		t.Fatalf("timeout mismatch: got %s want 45s", cfg.Timeout)
	}
	if cfg.OutputPath != "/tmp/postgres-e2e.out" {
		t.Fatalf("output mismatch: got %q", cfg.OutputPath)
	}
}

func TestRunMainWithRunnerQueryWritesStdout(t *testing.T) {
	t.Parallel()

	query := base64.StdEncoding.EncodeToString([]byte("SELECT value FROM foo"))
	runner := &fakePostgresRunner{queryResult: []string{"alpha", "beta"}}
	var out strings.Builder

	err := runMainWithRunner([]string{
		"--postgres-dsn", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
		"--query-base64", query,
	}, &out, runner)
	if err != nil {
		t.Fatalf("runMainWithRunner() error = %v", err)
	}
	if runner.queryHit != 1 {
		t.Fatalf("queryHit = %d, want 1", runner.queryHit)
	}
	if runner.gotSQL != "SELECT value FROM foo" {
		t.Fatalf("gotSQL = %q", runner.gotSQL)
	}
	if out.String() != "alpha\nbeta\n" {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestRunMainWithRunnerExecWritesEmptyFile(t *testing.T) {
	t.Parallel()

	execStmt := base64.StdEncoding.EncodeToString([]byte("DELETE FROM foo"))
	runner := &fakePostgresRunner{}
	outPath := filepath.Join(t.TempDir(), "postgres-e2e.out")
	var out bytes.Buffer

	err := runMainWithRunner([]string{
		"--postgres-dsn", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
		"--exec-base64", execStmt,
		"--output", outPath,
	}, &out, runner)
	if err != nil {
		t.Fatalf("runMainWithRunner() error = %v", err)
	}
	if runner.execHit != 1 {
		t.Fatalf("execHit = %d, want 1", runner.execHit)
	}
	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(content) != "" {
		t.Fatalf("output file = %q, want empty", string(content))
	}
}

func TestRunMainWithRunnerPropagatesRunnerErrors(t *testing.T) {
	t.Parallel()

	query := base64.StdEncoding.EncodeToString([]byte("SELECT value FROM foo"))
	runner := &fakePostgresRunner{queryErr: errors.New("boom")}
	var out strings.Builder

	err := runMainWithRunner([]string{
		"--postgres-dsn", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
		"--query-base64", query,
	}, &out, runner)
	if err == nil || !strings.Contains(err.Error(), "postgres query") {
		t.Fatalf("runMainWithRunner() error = %v, want postgres query error", err)
	}
}
