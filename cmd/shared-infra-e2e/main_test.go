package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/segmentio/kafka-go"
)

func TestParseArgs_Valid(t *testing.T) {
	t.Parallel()

	cfg, err := parseArgs([]string{
		"--postgres-dsn", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
		"--kafka-brokers", "127.0.0.1:9092,127.0.0.1:9093",
		"--required-kafka-topics", "checkpoints.signatures.v1,checkpoints.packages.v1",
		"--checkpoint-ipfs-api-url", "http://127.0.0.1:5001",
		"--checkpoint-min-persisted-at", "2026-01-02T03:04:05Z",
		"--checkpoint-operators", "0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222",
		"--checkpoint-threshold", "2",
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
	if len(cfg.RequiredKafkaTopics) != 2 {
		t.Fatalf("required kafka topics: got %d want 2", len(cfg.RequiredKafkaTopics))
	}
	if cfg.RequiredKafkaTopics[0] != "checkpoints.signatures.v1" {
		t.Fatalf("first required topic mismatch: %q", cfg.RequiredKafkaTopics[0])
	}
	if cfg.RequiredKafkaTopics[1] != "checkpoints.packages.v1" {
		t.Fatalf("second required topic mismatch: %q", cfg.RequiredKafkaTopics[1])
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
	if cfg.CheckpointMinPersistedAt.IsZero() {
		t.Fatalf("expected checkpoint min persisted timestamp")
	}
	if got := len(cfg.CheckpointOperators); got != 2 {
		t.Fatalf("checkpoint operators: got %d want 2", got)
	}
	if cfg.CheckpointThreshold != 2 {
		t.Fatalf("checkpoint threshold mismatch: got %d want 2", cfg.CheckpointThreshold)
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

func TestParseArgs_RejectsCheckpointThresholdWithoutOperators(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--postgres-dsn", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
		"--kafka-brokers", "127.0.0.1:9092",
		"--checkpoint-ipfs-api-url", "http://127.0.0.1:5001",
		"--checkpoint-threshold", "1",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--checkpoint-operators") {
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

func TestParseArgs_RequiredKafkaTopicsDedupAndTrim(t *testing.T) {
	t.Parallel()

	cfg, err := parseArgs([]string{
		"--postgres-dsn", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
		"--kafka-brokers", "127.0.0.1:9092",
		"--checkpoint-ipfs-api-url", "http://127.0.0.1:5001",
		"--required-kafka-topics", " checkpoints.signatures.v1,checkpoints.packages.v1,checkpoints.signatures.v1, ",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(cfg.RequiredKafkaTopics) != 2 {
		t.Fatalf("required kafka topics: got %d want 2", len(cfg.RequiredKafkaTopics))
	}
	if cfg.RequiredKafkaTopics[0] != "checkpoints.signatures.v1" || cfg.RequiredKafkaTopics[1] != "checkpoints.packages.v1" {
		t.Fatalf("unexpected required kafka topics: %#v", cfg.RequiredKafkaTopics)
	}
}

func TestKafkaTLSEnabledFromEnv(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "unset", value: "", want: false},
		{name: "false", value: "false", want: false},
		{name: "zero", value: "0", want: false},
		{name: "true", value: "true", want: true},
		{name: "one", value: "1", want: true},
		{name: "yes", value: "yes", want: true},
		{name: "on", value: "on", want: true},
		{name: "mixed case and spaces", value: "  TrUE ", want: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envQueueKafkaTLS, tc.value)
			if got := kafkaTLSEnabledFromEnv(); got != tc.want {
				t.Fatalf("kafkaTLSEnabledFromEnv(%q) = %t, want %t", tc.value, got, tc.want)
			}
		})
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

func TestCheckCheckpointIPFSWithSource_RejectsMismatchedSignatureSet(t *testing.T) {
	t.Parallel()

	const cid = "bafybeigdyrztmjnd3h6akxw2n3kq7hpvzd5xkz4a2xlfdgr3mxwct6f2da"

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		FinalOrchardRoot: common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		BaseChainID:      84532,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := checkpoint.Digest(cp)
	payload, err := json.Marshal(checkpointPackageV1{
		Version:         "checkpoints.package.v1",
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
		Signers: []common.Address{
			common.HexToAddress("0x1234567890123456789012345678901234567890"),
		},
		Signatures: []string{
			"0xdeadbeef",
		},
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	source := &stubCheckpointPackageSource{
		record: checkpointPackageRecord{
			Digest:      digest,
			IPFSCID:     cid,
			Payload:     payload,
			PersistedAt: time.Now().UTC(),
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v0/pin/ls":
			_, _ = io.WriteString(w, `{"Keys":{"`+cid+`":{"Type":"recursive"}}}`)
		case "/api/v0/cat":
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	_, err = checkCheckpointIPFSWithSource(context.Background(), config{
		PostgresDSN:          "postgresql://postgres:postgres@127.0.0.1:5432/intents_e2e?sslmode=disable",
		CheckpointIPFSAPIURL: srv.URL,
	}, source)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "verify checkpoint package signatures") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type stubCheckpointPackageSource struct {
	record checkpointPackageRecord
	err    error

	mu             sync.Mutex
	calls          int
	dsn            string
	minPersistedAt time.Time
}

func (s *stubCheckpointPackageSource) Latest(_ context.Context, postgresDSN string, minPersistedAt time.Time) (checkpointPackageRecord, error) {
	s.mu.Lock()
	s.calls++
	s.dsn = postgresDSN
	s.minPersistedAt = minPersistedAt
	s.mu.Unlock()
	if s.err != nil {
		return checkpointPackageRecord{}, s.err
	}
	return s.record, nil
}

func (s *stubCheckpointPackageSource) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *stubCheckpointPackageSource) DSN() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dsn
}

func (s *stubCheckpointPackageSource) MinPersistedAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.minPersistedAt
}

func TestCheckCheckpointIPFSWithSource_ValidatesOperatorProducedPackage(t *testing.T) {
	t.Parallel()

	const (
		cid         = "bafybeigdyrztmjnd3h6akxw2n3kq7hpvzd5xkz4a2xlfdgr3mxwct6f2da"
		postgresDSN = "postgresql://postgres:postgres@127.0.0.1:5432/intents_e2e?sslmode=disable"
	)

	key, err := crypto.HexToECDSA("4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		FinalOrchardRoot: common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		BaseChainID:      84532,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := checkpoint.Digest(cp)
	sig, err := checkpoint.SignDigest(key, digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	operator := crypto.PubkeyToAddress(key.PublicKey)
	payload, err := json.Marshal(checkpointPackageV1{
		Version:         "checkpoints.package.v1",
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
		Signers:         []common.Address{operator},
		Signatures:      []string{"0x" + hex.EncodeToString(sig)},
		CreatedAt:       time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	source := &stubCheckpointPackageSource{
		record: checkpointPackageRecord{
			Digest:      digest,
			IPFSCID:     cid,
			Payload:     payload,
			PersistedAt: time.Now().UTC(),
		},
	}

	addCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v0/add":
			addCalls++
			http.Error(w, "unexpected add call", http.StatusBadRequest)
		case "/api/v0/pin/ls":
			_, _ = io.WriteString(w, `{"Keys":{"`+cid+`":{"Type":"recursive"}}}`)
		case "/api/v0/cat":
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	rep, err := checkCheckpointIPFSWithSource(context.Background(), config{
		PostgresDSN:          postgresDSN,
		CheckpointIPFSAPIURL: srv.URL,
	}, source)
	if err != nil {
		t.Fatalf("checkCheckpointIPFSWithSource: %v", err)
	}
	if rep.CID != cid {
		t.Fatalf("cid mismatch: got %q want %q", rep.CID, cid)
	}
	if rep.Digest != digest.Hex() {
		t.Fatalf("digest mismatch: got %q want %q", rep.Digest, digest.Hex())
	}
	if rep.SignerCount != 1 {
		t.Fatalf("signer count mismatch: got %d want 1", rep.SignerCount)
	}
	if rep.Threshold != 1 {
		t.Fatalf("threshold mismatch: got %d want 1", rep.Threshold)
	}
	if rep.PublishRoundTripMS != 0 {
		t.Fatalf("publish round trip mismatch: got %d want 0", rep.PublishRoundTripMS)
	}
	if rep.FetchRoundTripMS < 0 {
		t.Fatalf("fetch round trip must be >= 0, got %d", rep.FetchRoundTripMS)
	}
	if source.Calls() != 1 {
		t.Fatalf("source calls: got %d want 1", source.Calls())
	}
	if source.DSN() != postgresDSN {
		t.Fatalf("source dsn mismatch: got %q want %q", source.DSN(), postgresDSN)
	}
	if addCalls != 0 {
		t.Fatalf("unexpected ipfs add calls: got %d want 0", addCalls)
	}
}

func TestCheckCheckpointIPFSWithSource_RejectsSignerOutsideExpectedSet(t *testing.T) {
	t.Parallel()

	const cid = "bafybeigdyrztmjnd3h6akxw2n3kq7hpvzd5xkz4a2xlfdgr3mxwct6f2da"

	key, err := crypto.HexToECDSA("4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}
	operator := crypto.PubkeyToAddress(key.PublicKey)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		FinalOrchardRoot: common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		BaseChainID:      84532,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := checkpoint.Digest(cp)
	sig, err := checkpoint.SignDigest(key, digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	payload, err := json.Marshal(checkpointPackageV1{
		Version:         "checkpoints.package.v1",
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
		Signers:         []common.Address{operator},
		Signatures:      []string{"0x" + hex.EncodeToString(sig)},
		CreatedAt:       time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	source := &stubCheckpointPackageSource{
		record: checkpointPackageRecord{
			Digest:      digest,
			IPFSCID:     cid,
			Payload:     payload,
			PersistedAt: time.Now().UTC(),
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v0/pin/ls":
			_, _ = io.WriteString(w, `{"Keys":{"`+cid+`":{"Type":"recursive"}}}`)
		case "/api/v0/cat":
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	_, err = checkCheckpointIPFSWithSource(context.Background(), config{
		PostgresDSN:          "postgresql://postgres:postgres@127.0.0.1:5432/intents_e2e?sslmode=disable",
		CheckpointIPFSAPIURL: srv.URL,
		CheckpointOperators: []common.Address{
			common.HexToAddress("0x1000000000000000000000000000000000000001"),
		},
		CheckpointThreshold: 1,
	}, source)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "unexpected checkpoint signer") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckCheckpointIPFSWithSource_RejectsBelowThreshold(t *testing.T) {
	t.Parallel()

	const cid = "bafybeigdyrztmjnd3h6akxw2n3kq7hpvzd5xkz4a2xlfdgr3mxwct6f2da"

	key, err := crypto.HexToECDSA("4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}
	operator := crypto.PubkeyToAddress(key.PublicKey)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		FinalOrchardRoot: common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		BaseChainID:      84532,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := checkpoint.Digest(cp)
	sig, err := checkpoint.SignDigest(key, digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	payload, err := json.Marshal(checkpointPackageV1{
		Version:         "checkpoints.package.v1",
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
		Signers:         []common.Address{operator},
		Signatures:      []string{"0x" + hex.EncodeToString(sig)},
		CreatedAt:       time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	source := &stubCheckpointPackageSource{
		record: checkpointPackageRecord{
			Digest:      digest,
			IPFSCID:     cid,
			Payload:     payload,
			PersistedAt: time.Now().UTC(),
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v0/pin/ls":
			_, _ = io.WriteString(w, `{"Keys":{"`+cid+`":{"Type":"recursive"}}}`)
		case "/api/v0/cat":
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	_, err = checkCheckpointIPFSWithSource(context.Background(), config{
		PostgresDSN:          "postgresql://postgres:postgres@127.0.0.1:5432/intents_e2e?sslmode=disable",
		CheckpointIPFSAPIURL: srv.URL,
		CheckpointOperators:  []common.Address{operator},
		CheckpointThreshold:  2,
	}, source)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "checkpoint signer count below threshold") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckCheckpointIPFSWithSource_ForwardsMinPersistedAt(t *testing.T) {
	t.Parallel()

	const cid = "bafybeigdyrztmjnd3h6akxw2n3kq7hpvzd5xkz4a2xlfdgr3mxwct6f2da"
	minPersistedAt := time.Date(2026, 2, 1, 3, 4, 5, 0, time.UTC)

	key, err := crypto.HexToECDSA("4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}
	operator := crypto.PubkeyToAddress(key.PublicKey)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		FinalOrchardRoot: common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		BaseChainID:      84532,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := checkpoint.Digest(cp)
	sig, err := checkpoint.SignDigest(key, digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	payload, err := json.Marshal(checkpointPackageV1{
		Version:         "checkpoints.package.v1",
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
		Signers:         []common.Address{operator},
		Signatures:      []string{"0x" + hex.EncodeToString(sig)},
		CreatedAt:       time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	source := &stubCheckpointPackageSource{
		record: checkpointPackageRecord{
			Digest:      digest,
			IPFSCID:     cid,
			Payload:     payload,
			PersistedAt: time.Now().UTC(),
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v0/pin/ls":
			_, _ = io.WriteString(w, `{"Keys":{"`+cid+`":{"Type":"recursive"}}}`)
		case "/api/v0/cat":
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	_, err = checkCheckpointIPFSWithSource(context.Background(), config{
		PostgresDSN:               "postgresql://postgres:postgres@127.0.0.1:5432/intents_e2e?sslmode=disable",
		CheckpointIPFSAPIURL:      srv.URL,
		CheckpointOperators:       []common.Address{operator},
		CheckpointThreshold:       1,
		CheckpointMinPersistedAt:  minPersistedAt,
	}, source)
	if err != nil {
		t.Fatalf("checkCheckpointIPFSWithSource: %v", err)
	}
	if got := source.MinPersistedAt(); !got.Equal(minPersistedAt) {
		t.Fatalf("min persisted at mismatch: got=%s want=%s", got.UTC().Format(time.RFC3339), minPersistedAt.UTC().Format(time.RFC3339))
	}
}
