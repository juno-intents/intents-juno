package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type config struct {
	PostgresDSN string
	QueryBase64 string
	ExecBase64  string
	Timeout     time.Duration
	OutputPath  string
}

type postgresRunner interface {
	Query(ctx context.Context, dsn, sql string) ([]string, error)
	Exec(ctx context.Context, dsn, sql string) error
}

type livePostgresRunner struct{}

func main() {
	if err := runMain(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runMain(args []string, stdout io.Writer) error {
	return runMainWithRunner(args, stdout, livePostgresRunner{})
}

func runMainWithRunner(args []string, stdout io.Writer, runner postgresRunner) error {
	cfg, err := parseArgs(args)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	if cfg.QueryBase64 != "" {
		query, err := decodeSQLBase64(cfg.QueryBase64)
		if err != nil {
			return fmt.Errorf("decode --query-base64: %w", err)
		}
		lines, err := runner.Query(ctx, cfg.PostgresDSN, query)
		if err != nil {
			return fmt.Errorf("postgres query: %w", err)
		}
		output := strings.Join(lines, "\n")
		if len(lines) > 0 {
			output += "\n"
		}
		return writeOutput(cfg.OutputPath, stdout, output)
	}

	stmt, err := decodeSQLBase64(cfg.ExecBase64)
	if err != nil {
		return fmt.Errorf("decode --exec-base64: %w", err)
	}
	if err := runner.Exec(ctx, cfg.PostgresDSN, stmt); err != nil {
		return fmt.Errorf("postgres exec: %w", err)
	}
	return writeOutput(cfg.OutputPath, stdout, "")
}

func parseArgs(args []string) (config, error) {
	var cfg config

	fs := flag.NewFlagSet("postgres-e2e", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&cfg.PostgresDSN, "postgres-dsn", "", "Postgres DSN (required)")
	fs.StringVar(&cfg.QueryBase64, "query-base64", "", "base64-encoded SQL query to execute")
	fs.StringVar(&cfg.ExecBase64, "exec-base64", "", "base64-encoded SQL statement to execute")
	fs.DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "overall timeout")
	fs.StringVar(&cfg.OutputPath, "output", "-", "output path or '-' for stdout")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	cfg.PostgresDSN = strings.TrimSpace(cfg.PostgresDSN)
	cfg.QueryBase64 = strings.TrimSpace(cfg.QueryBase64)
	cfg.ExecBase64 = strings.TrimSpace(cfg.ExecBase64)
	cfg.OutputPath = strings.TrimSpace(cfg.OutputPath)

	if cfg.PostgresDSN == "" {
		return cfg, errors.New("--postgres-dsn is required")
	}
	if (cfg.QueryBase64 == "") == (cfg.ExecBase64 == "") {
		return cfg, errors.New("exactly one of --query-base64 or --exec-base64 is required")
	}
	if cfg.Timeout <= 0 {
		return cfg, errors.New("--timeout must be > 0")
	}
	if cfg.OutputPath == "" {
		return cfg, errors.New("--output must not be empty")
	}

	return cfg, nil
}

func decodeSQLBase64(raw string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	sql := strings.TrimSpace(string(decoded))
	if sql == "" {
		return "", errors.New("decoded sql is empty")
	}
	return sql, nil
}

func writeOutput(path string, stdout io.Writer, content string) error {
	if path == "-" {
		_, err := io.WriteString(stdout, content)
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func (livePostgresRunner) Query(ctx context.Context, dsn, sql string) ([]string, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("new pool: %w", err)
	}
	defer pool.Close()

	rows, err := pool.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	lines := make([]string, 0)
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}
		if len(values) == 0 || values[0] == nil {
			lines = append(lines, "")
			continue
		}
		switch v := values[0].(type) {
		case []byte:
			lines = append(lines, string(v))
		case string:
			lines = append(lines, v)
		default:
			lines = append(lines, fmt.Sprint(v))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func (livePostgresRunner) Exec(ctx context.Context, dsn, sql string) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("new pool: %w", err)
	}
	defer pool.Close()

	_, err = pool.Exec(ctx, sql)
	return err
}
