package proofrequestor

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/boundless"
	"github.com/juno-intents/intents-juno/internal/proof"
	"github.com/juno-intents/intents-juno/internal/queue"
)

func TestWorker_E2E_FulfillmentDeterministic(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 11, 14, 0, 0, 0, time.UTC)
	store := proof.NewMemoryStore(func() time.Time { return now })
	submitter := &stubSubmitter{
		offchainResp: boundless.SubmitResponse{
			RequestID:      1,
			SubmissionPath: "offchain",
			Seal:           []byte{0x99},
		},
	}
	svc, err := New(Config{
		Owner:                      "requestor-e2e",
		ChainID:                    8453,
		RequestTimeout:             5 * time.Second,
		CallbackIdempotencyTTL:     72 * time.Hour,
		SubmissionMode:             boundless.SubmissionModeOffchainPrimaryOnchainFallback,
		OnchainFallbackEnabled:     true,
		OnchainFallbackFundingMode: boundless.FundingModeMinMaxBalance,
	}, store, submitter, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	inputPayload := `{"job_id":"0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98","pipeline":"deposit","image_id":"0x000000000000000000000000000000000000000000000000000000000000aa01","journal":"0x01","private_input":"0x02","deadline":"2026-02-11T14:05:00Z","priority":1}` + "\n"
	consumer, err := queue.NewConsumer(context.Background(), queue.ConsumerConfig{
		Driver: queue.DriverStdio,
		Reader: strings.NewReader(inputPayload),
	})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	var out bytes.Buffer
	producer, err := queue.NewProducer(queue.ProducerConfig{
		Driver: queue.DriverStdio,
		Writer: &out,
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()

	worker, err := NewWorker(WorkerConfig{
		InputTopic:   "proof.requests.v1",
		ResultTopic:  "proof.fulfillments.v1",
		FailureTopic: "proof.failures.v1",
		MaxInflight:  4,
		AckTimeout:   time.Second,
	}, svc, consumer, producer, nil)
	if err != nil {
		t.Fatalf("NewWorker: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := worker.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one output message, got %d: %q", len(lines), out.String())
	}
	var msg struct {
		Version   string `json:"version"`
		JobID     string `json:"job_id"`
		RequestID uint64 `json:"request_id"`
		Seal      string `json:"seal"`
		Journal   string `json:"journal"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &msg); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if msg.Version != "proof.fulfillment.v1" {
		t.Fatalf("version: got %q", msg.Version)
	}
	if msg.JobID != common.HexToHash("0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98").Hex() {
		t.Fatalf("job id: got %q", msg.JobID)
	}
	if msg.RequestID != 1 {
		t.Fatalf("request id: got %d want 1", msg.RequestID)
	}
	if got, want := msg.Journal, "0x01"; got != want {
		t.Fatalf("journal: got %q want %q", got, want)
	}
}

func TestWorker_E2E_FailurePublished(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 11, 14, 30, 0, 0, time.UTC)
	store := proof.NewMemoryStore(func() time.Time { return now })
	submitter := &stubSubmitter{offchainErr: &boundless.SubmitError{Code: "upstream_timeout", Retryable: true, Cause: context.DeadlineExceeded}}

	svc, err := New(Config{
		Owner:                      "requestor-e2e",
		ChainID:                    8453,
		RequestTimeout:             5 * time.Second,
		CallbackIdempotencyTTL:     72 * time.Hour,
		SubmissionMode:             boundless.SubmissionModeOffchainPrimaryOnchainFallback,
		OnchainFallbackEnabled:     false,
		OnchainFallbackFundingMode: boundless.FundingModeMinMaxBalance,
	}, store, submitter, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	inputPayload := `{"job_id":"0x4314e7904fd1808ad5a2394a4e8e6cf6ccf8802f27195be7d87da01f5c23a1ee","pipeline":"withdraw","image_id":"0x000000000000000000000000000000000000000000000000000000000000aa02","journal":"0x01","private_input":"0x02","deadline":"2026-02-11T14:35:00Z","priority":2}` + "\n"
	consumer, err := queue.NewConsumer(context.Background(), queue.ConsumerConfig{
		Driver: queue.DriverStdio,
		Reader: strings.NewReader(inputPayload),
	})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	var out bytes.Buffer
	producer, err := queue.NewProducer(queue.ProducerConfig{
		Driver: queue.DriverStdio,
		Writer: &out,
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()

	worker, err := NewWorker(WorkerConfig{
		InputTopic:   "proof.requests.v1",
		ResultTopic:  "proof.fulfillments.v1",
		FailureTopic: "proof.failures.v1",
		MaxInflight:  2,
		AckTimeout:   time.Second,
	}, svc, consumer, producer, nil)
	if err != nil {
		t.Fatalf("NewWorker: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := worker.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one output message, got %d: %q", len(lines), out.String())
	}
	var msg struct {
		Version   string `json:"version"`
		JobID     string `json:"job_id"`
		ErrorCode string `json:"error_code"`
		Retryable bool   `json:"retryable"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &msg); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if msg.Version != "proof.failure.v1" {
		t.Fatalf("version: got %q", msg.Version)
	}
	if msg.ErrorCode == "" || !msg.Retryable {
		t.Fatalf("unexpected failure payload: %+v", msg)
	}
}
