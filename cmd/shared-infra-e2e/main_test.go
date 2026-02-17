package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseArgs_Valid(t *testing.T) {
	t.Parallel()

	cfg, err := parseArgs([]string{
		"--postgres-dsn", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
		"--kafka-brokers", "127.0.0.1:9092,127.0.0.1:9093",
		"--topic-prefix", "shared.e2e",
		"--timeout", "90s",
		"--output", "/tmp/shared-report.json",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}

	if cfg.PostgresDSN == "" {
		t.Fatalf("expected postgres dsn")
	}
	if len(cfg.KafkaBrokers) != 2 {
		t.Fatalf("kafka brokers: got %d want 2", len(cfg.KafkaBrokers))
	}
	if cfg.KafkaBrokers[0] != "127.0.0.1:9092" {
		t.Fatalf("first broker mismatch: %q", cfg.KafkaBrokers[0])
	}
	if cfg.TopicPrefix != "shared.e2e" {
		t.Fatalf("topic prefix mismatch: %q", cfg.TopicPrefix)
	}
	if cfg.Timeout != 90*time.Second {
		t.Fatalf("timeout mismatch: %s", cfg.Timeout)
	}
	if cfg.OutputPath != "/tmp/shared-report.json" {
		t.Fatalf("output path mismatch: %q", cfg.OutputPath)
	}
}

func TestParseArgs_RequiresPostgresDSN(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--kafka-brokers", "127.0.0.1:9092",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--postgres-dsn") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseArgs_RequiresKafkaBrokers(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--postgres-dsn", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--kafka-brokers") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseArgs_RejectsZeroTimeout(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--postgres-dsn", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
		"--kafka-brokers", "127.0.0.1:9092",
		"--timeout", "0s",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--timeout") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseBrokers_DedupAndTrim(t *testing.T) {
	t.Parallel()

	got := parseBrokers(" 127.0.0.1:9092,127.0.0.1:9093,127.0.0.1:9092,, ")
	if len(got) != 2 {
		t.Fatalf("brokers length: got %d want 2", len(got))
	}
	if got[0] != "127.0.0.1:9092" || got[1] != "127.0.0.1:9093" {
		t.Fatalf("unexpected brokers: %#v", got)
	}
}
