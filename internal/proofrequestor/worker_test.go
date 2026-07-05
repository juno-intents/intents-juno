package proofrequestor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/dlq"
	"github.com/juno-intents/intents-juno/internal/proof"
	"github.com/juno-intents/intents-juno/internal/queue"
)

type workerTestProducer struct {
	err         error
	calls       int
	topic       string
	targetGroup string
	payload     []byte
}

func (p *workerTestProducer) Publish(_ context.Context, topic string, payload []byte) error {
	p.calls++
	p.topic = topic
	p.targetGroup = ""
	p.payload = append([]byte(nil), payload...)
	return p.err
}

func (p *workerTestProducer) Close() error { return nil }

func (p *workerTestProducer) PublishToGroup(_ context.Context, topic string, group string, payload []byte) error {
	p.calls++
	p.topic = topic
	p.targetGroup = group
	p.payload = append([]byte(nil), payload...)
	return p.err
}

type workerTestDLQStore struct {
	insertErr error
	records   []dlq.ProofDLQRecord
}

func (s *workerTestDLQStore) EnsureSchema(context.Context) error { return nil }

func (s *workerTestDLQStore) InsertProofDLQ(_ context.Context, rec dlq.ProofDLQRecord) error {
	if s.insertErr != nil {
		return s.insertErr
	}
	s.records = append(s.records, rec)
	return nil
}

func (s *workerTestDLQStore) InsertDepositBatchDLQ(context.Context, dlq.DepositBatchDLQRecord) error {
	return errors.New("unexpected InsertDepositBatchDLQ")
}

func (s *workerTestDLQStore) InsertWithdrawalBatchDLQ(context.Context, dlq.WithdrawalBatchDLQRecord) error {
	return errors.New("unexpected InsertWithdrawalBatchDLQ")
}

func (s *workerTestDLQStore) ListProofDLQ(context.Context, dlq.DLQFilter) ([]dlq.ProofDLQRecord, error) {
	return nil, errors.New("unexpected ListProofDLQ")
}

func (s *workerTestDLQStore) ListDepositBatchDLQ(context.Context, dlq.DLQFilter) ([]dlq.DepositBatchDLQRecord, error) {
	return nil, errors.New("unexpected ListDepositBatchDLQ")
}

func (s *workerTestDLQStore) ListWithdrawalBatchDLQ(context.Context, dlq.DLQFilter) ([]dlq.WithdrawalBatchDLQRecord, error) {
	return nil, errors.New("unexpected ListWithdrawalBatchDLQ")
}

func (s *workerTestDLQStore) CountUnacknowledged(context.Context) (dlq.DLQCounts, error) {
	return dlq.DLQCounts{}, errors.New("unexpected CountUnacknowledged")
}

func (s *workerTestDLQStore) Acknowledge(context.Context, string, []byte) error {
	return errors.New("unexpected Acknowledge")
}

func newAckingMessage(topic string, payload []byte, ackFn func(context.Context) error) queue.Message {
	msg := queue.Message{
		Topic: topic,
		Value: payload,
	}
	field := reflect.ValueOf(&msg).Elem().FieldByName("ackFn")
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(ackFn))
	return msg
}

func TestWorker_HandleMalformedRequestDoesNotAckWhenFailurePublishFails(t *testing.T) {
	t.Parallel()

	producerErr := errors.New("publish failed")
	producer := &workerTestProducer{err: producerErr}
	worker := &Worker{
		cfg: WorkerConfig{
			FailureTopic: "proof.failures.v1",
			AckTimeout:   time.Second,
		},
		producer: producer,
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	acked := false
	msg := newAckingMessage("proof.requests.v1", []byte(`not-json`), func(context.Context) error {
		acked = true
		return nil
	})

	err := worker.handleMessage(context.Background(), msg)
	if !errors.Is(err, producerErr) {
		t.Fatalf("handleMessage error = %v, want %v", err, producerErr)
	}
	if acked {
		t.Fatalf("expected malformed request to remain unacked on publish failure")
	}
}

func TestWorker_HandleMalformedRequestDoesNotAckWhenDLQInsertFails(t *testing.T) {
	t.Parallel()

	dlqErr := errors.New("dlq unavailable")
	producer := &workerTestProducer{}
	worker := &Worker{
		cfg: WorkerConfig{
			FailureTopic: "proof.failures.v1",
			AckTimeout:   time.Second,
			DLQStore:     &workerTestDLQStore{insertErr: dlqErr},
		},
		producer: producer,
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	acked := false
	msg := newAckingMessage("proof.requests.v1", []byte(`not-json`), func(context.Context) error {
		acked = true
		return nil
	})

	err := worker.handleMessage(context.Background(), msg)
	if !errors.Is(err, dlqErr) {
		t.Fatalf("handleMessage error = %v, want %v", err, dlqErr)
	}
	if acked {
		t.Fatalf("expected malformed request to remain unacked on DLQ failure")
	}
	if producer.calls != 0 {
		t.Fatalf("failure publish calls = %d, want 0 when DLQ persistence fails first", producer.calls)
	}
}

func TestWorker_HandleFulfilledRequestPublishesToResponseGroup(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 5, 2, 0, 0, 0, time.UTC)
	store := proof.NewMemoryStore(func() time.Time { return now })
	prover := &stubProver{seal: []byte{0x99}}
	svc, err := New(Config{
		Owner:                  "requestor-a",
		ChainID:                8453,
		RequestTimeout:         5 * time.Second,
		CallbackIdempotencyTTL: 72 * time.Hour,
	}, store, prover, nil)
	if err != nil {
		t.Fatalf("New service: %v", err)
	}

	producer := &workerTestProducer{}
	worker := &Worker{
		cfg: WorkerConfig{
			ResultTopic:  "proof.fulfillments.v1",
			FailureTopic: "proof.failures.v1",
			AckTimeout:   time.Second,
		},
		service:  svc,
		producer: producer,
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	acked := false
	payload := []byte(`{"job_id":"0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98","pipeline":"deposit","image_id":"0x000000000000000000000000000000000000000000000000000000000000aa01","journal":"0x01","private_input":"0x02","deadline":"2026-07-05T02:05:00Z","priority":1,"response_group":"ip-10-92-1-179-deposit-relayer-proof"}`)
	msg := newAckingMessage("proof.requests.v1", payload, func(context.Context) error {
		acked = true
		return nil
	})

	if err := worker.handleMessage(context.Background(), msg); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}
	if !acked {
		t.Fatalf("expected request message to be acked")
	}
	if got, want := producer.topic, "proof.fulfillments.v1"; got != want {
		t.Fatalf("publish topic = %q, want %q", got, want)
	}
	if got, want := producer.targetGroup, "ip-10-92-1-179-deposit-relayer-proof"; got != want {
		t.Fatalf("target group = %q, want %q", got, want)
	}
	var out struct {
		Version string `json:"version"`
		JobID   string `json:"job_id"`
	}
	if err := json.Unmarshal(producer.payload, &out); err != nil {
		t.Fatalf("decode response payload: %v", err)
	}
	if got, want := out.Version, "proof.fulfillment.v1"; got != want {
		t.Fatalf("response version = %q, want %q", got, want)
	}
	if got, want := out.JobID, common.HexToHash("0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98").Hex(); got != want {
		t.Fatalf("job id = %q, want %q", got, want)
	}
}

func TestWorker_HandleActiveDuplicatePublishesRetryableFailureToResponseGroup(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 5, 2, 30, 0, 0, time.UTC)
	store := proof.NewMemoryStore(func() time.Time { return now })
	job := proof.JobRequest{
		JobID:        common.HexToHash("0x7a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98"),
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     now.Add(5 * time.Minute),
		Priority:     1,
	}
	if _, err := store.UpsertJob(context.Background(), job, 72*time.Hour); err != nil {
		t.Fatalf("UpsertJob: %v", err)
	}
	if _, claimed, err := store.ClaimForSubmission(context.Background(), job.JobID, "requestor-a", 5*time.Minute, 8453); err != nil {
		t.Fatalf("ClaimForSubmission: %v", err)
	} else if !claimed {
		t.Fatalf("expected first claim")
	}

	prover := &stubProver{seal: []byte{0x99}}
	svc, err := New(Config{
		Owner:                  "requestor-a",
		ChainID:                8453,
		RequestTimeout:         5 * time.Second,
		CallbackIdempotencyTTL: 72 * time.Hour,
	}, store, prover, nil)
	if err != nil {
		t.Fatalf("New service: %v", err)
	}

	producer := &workerTestProducer{}
	worker := &Worker{
		cfg: WorkerConfig{
			ResultTopic:  "proof.fulfillments.v1",
			FailureTopic: "proof.failures.v1",
			AckTimeout:   time.Second,
		},
		service:  svc,
		producer: producer,
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	acked := false
	payload := []byte(`{"job_id":"0x7a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98","pipeline":"deposit","image_id":"0x000000000000000000000000000000000000000000000000000000000000aa01","journal":"0x01","private_input":"0x02","deadline":"2026-07-05T02:35:00Z","priority":1,"response_group":"ip-10-93-1-139-deposit-relayer-proof"}`)
	msg := newAckingMessage("proof.requests.v1", payload, func(context.Context) error {
		acked = true
		return nil
	})

	if err := worker.handleMessage(context.Background(), msg); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}
	if !acked {
		t.Fatalf("expected duplicate request message to be acked after response")
	}
	if got, want := producer.topic, "proof.failures.v1"; got != want {
		t.Fatalf("publish topic = %q, want %q", got, want)
	}
	if got, want := producer.targetGroup, "ip-10-93-1-139-deposit-relayer-proof"; got != want {
		t.Fatalf("target group = %q, want %q", got, want)
	}
	var out struct {
		Version   string `json:"version"`
		JobID     string `json:"job_id"`
		ErrorCode string `json:"error_code"`
		Retryable bool   `json:"retryable"`
	}
	if err := json.Unmarshal(producer.payload, &out); err != nil {
		t.Fatalf("decode failure payload: %v", err)
	}
	if got, want := out.Version, "proof.failure.v1"; got != want {
		t.Fatalf("response version = %q, want %q", got, want)
	}
	if got, want := out.JobID, job.JobID.Hex(); got != want {
		t.Fatalf("job id = %q, want %q", got, want)
	}
	if got, want := out.ErrorCode, "proof_request_in_progress"; got != want {
		t.Fatalf("error code = %q, want %q", got, want)
	}
	if !out.Retryable {
		t.Fatalf("expected retryable duplicate failure")
	}
	if prover.calls != 0 {
		t.Fatalf("prove calls = %d, want 0", prover.calls)
	}
}

func TestWorker_HandleMismatchedDuplicatePublishesTerminalFailureToResponseGroup(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 5, 3, 0, 0, 0, time.UTC)
	store := proof.NewMemoryStore(func() time.Time { return now })
	existing := proof.JobRequest{
		JobID:        common.HexToHash("0x8a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98"),
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     now.Add(5 * time.Minute),
		Priority:     1,
	}
	if _, err := store.UpsertJob(context.Background(), existing, 72*time.Hour); err != nil {
		t.Fatalf("UpsertJob: %v", err)
	}

	prover := &stubProver{seal: []byte{0x99}}
	svc, err := New(Config{
		Owner:                  "requestor-a",
		ChainID:                8453,
		RequestTimeout:         5 * time.Second,
		CallbackIdempotencyTTL: 72 * time.Hour,
	}, store, prover, nil)
	if err != nil {
		t.Fatalf("New service: %v", err)
	}

	producer := &workerTestProducer{}
	worker := &Worker{
		cfg: WorkerConfig{
			ResultTopic:  "proof.fulfillments.v1",
			FailureTopic: "proof.failures.v1",
			AckTimeout:   time.Second,
		},
		service:  svc,
		producer: producer,
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	acked := false
	payload := []byte(`{"job_id":"0x8a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98","pipeline":"deposit","image_id":"0x000000000000000000000000000000000000000000000000000000000000aa01","journal":"0x03","private_input":"0x04","deadline":"2026-07-05T03:05:00Z","priority":1,"response_group":"ip-10-94-1-229-deposit-relayer-proof"}`)
	msg := newAckingMessage("proof.requests.v1", payload, func(context.Context) error {
		acked = true
		return nil
	})

	if err := worker.handleMessage(context.Background(), msg); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}
	if !acked {
		t.Fatalf("expected mismatched request message to be acked after response")
	}
	if got, want := producer.topic, "proof.failures.v1"; got != want {
		t.Fatalf("publish topic = %q, want %q", got, want)
	}
	if got, want := producer.targetGroup, "ip-10-94-1-229-deposit-relayer-proof"; got != want {
		t.Fatalf("target group = %q, want %q", got, want)
	}
	var out struct {
		Version   string `json:"version"`
		JobID     string `json:"job_id"`
		ErrorCode string `json:"error_code"`
		Retryable bool   `json:"retryable"`
	}
	if err := json.Unmarshal(producer.payload, &out); err != nil {
		t.Fatalf("decode failure payload: %v", err)
	}
	if got, want := out.Version, "proof.failure.v1"; got != want {
		t.Fatalf("response version = %q, want %q", got, want)
	}
	if got, want := out.JobID, existing.JobID.Hex(); got != want {
		t.Fatalf("job id = %q, want %q", got, want)
	}
	if got, want := out.ErrorCode, "proof_request_mismatch"; got != want {
		t.Fatalf("error code = %q, want %q", got, want)
	}
	if out.Retryable {
		t.Fatalf("expected terminal mismatch failure")
	}
	if prover.calls != 0 {
		t.Fatalf("prove calls = %d, want 0", prover.calls)
	}
}
