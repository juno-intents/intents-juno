package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
)

func TestParseArgs_Valid(t *testing.T) {
	t.Parallel()

	cfg, err := parseArgs([]string{
		"--postgres-dsn", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
		"--kafka-brokers", "127.0.0.1:9092,127.0.0.1:9093",
		"--checkpoint-ipfs-api-url", "http://127.0.0.1:5001",
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
		"--checkpoint-ipfs-api-url", "http://127.0.0.1:5001",
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
		"--checkpoint-ipfs-api-url", "http://127.0.0.1:5001",
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
		"--checkpoint-ipfs-api-url", "http://127.0.0.1:5001",
		"--timeout", "0s",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--timeout") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseArgs_RequiresCheckpointIPFSAPIURL(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--postgres-dsn", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
		"--kafka-brokers", "127.0.0.1:9092",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--checkpoint-ipfs-api-url") {
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

func TestIsTopicAlreadyExistsError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "exact",
			err:  kafka.TopicAlreadyExists,
			want: true,
		},
		{
			name: "wrapped",
			err:  fmt.Errorf("wrapped: %w", kafka.TopicAlreadyExists),
			want: true,
		},
		{
			name: "different kafka error",
			err:  kafka.UnknownTopicOrPartition,
			want: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isTopicAlreadyExistsError(tc.err)
			if got != tc.want {
				t.Fatalf("isTopicAlreadyExistsError() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCheckCheckpointIPFS_PublishPinAndFetch(t *testing.T) {
	t.Parallel()

	const cid = "bafybeigdyrztmjnd3h6akxw2n3kq7hpvzd5xkz4a2xlfdgr3mxwct6f2da"

	var (
		mu         sync.Mutex
		payloadByC = make(map[string][]byte)
		addCalls   int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v0/add":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			mr, err := r.MultipartReader()
			if err != nil {
				http.Error(w, "bad multipart", http.StatusBadRequest)
				return
			}
			var payload []byte
			for {
				part, err := mr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					http.Error(w, "multipart read error", http.StatusBadRequest)
					return
				}
				b, err := io.ReadAll(part)
				if err != nil {
					http.Error(w, "multipart part read error", http.StatusBadRequest)
					return
				}
				if part.FormName() == "file" {
					payload = b
				}
			}
			if len(payload) == 0 {
				http.Error(w, "missing file payload", http.StatusBadRequest)
				return
			}
			mu.Lock()
			addCalls++
			payloadByC[cid] = append([]byte(nil), payload...)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"Name":"checkpoint-package.json","Hash":"`+cid+`","Size":"1234"}`)
		case "/api/v0/pin/ls":
			arg := strings.TrimSpace(r.URL.Query().Get("arg"))
			mu.Lock()
			_, ok := payloadByC[arg]
			mu.Unlock()
			if !ok {
				http.Error(w, "pin not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"Keys":{"`+arg+`":{"Type":"recursive"}}}`)
		case "/api/v0/cat":
			arg := strings.TrimSpace(r.URL.Query().Get("arg"))
			mu.Lock()
			payload, ok := payloadByC[arg]
			mu.Unlock()
			if !ok {
				http.Error(w, "cid not found", http.StatusNotFound)
				return
			}
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	rep, err := checkCheckpointIPFS(context.Background(), config{
		CheckpointIPFSAPIURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("checkCheckpointIPFS: %v", err)
	}
	if rep.CID != cid {
		t.Fatalf("cid mismatch: got %q want %q", rep.CID, cid)
	}
	if rep.Digest == "" {
		t.Fatalf("expected digest in report")
	}
	if rep.SignerCount != 3 {
		t.Fatalf("signer count mismatch: got %d want 3", rep.SignerCount)
	}
	if rep.Threshold != 3 {
		t.Fatalf("threshold mismatch: got %d want 3", rep.Threshold)
	}
	if rep.PublishRoundTripMS < 0 {
		t.Fatalf("publish round trip must be >= 0, got %d", rep.PublishRoundTripMS)
	}
	if rep.FetchRoundTripMS < 0 {
		t.Fatalf("fetch round trip must be >= 0, got %d", rep.FetchRoundTripMS)
	}

	mu.Lock()
	raw := append([]byte(nil), payloadByC[cid]...)
	calls := addCalls
	mu.Unlock()
	if calls != 1 {
		t.Fatalf("ipfs add calls: got %d want 1", calls)
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("checkpoint payload is not valid json: %v", err)
	}
	if got := payload["version"]; got != "checkpoints.package.v1" {
		t.Fatalf("version mismatch: got %#v want %q", got, "checkpoints.package.v1")
	}
}
