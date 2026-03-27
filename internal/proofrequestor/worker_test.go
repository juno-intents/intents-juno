package proofrequestor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/juno-intents/intents-juno/internal/dlq"
	"github.com/juno-intents/intents-juno/internal/queue"
)

type workerTestProducer struct {
	err   error
	calls int
}

func (p *workerTestProducer) Publish(context.Context, string, []byte) error {
	p.calls++
	return p.err
}

func (p *workerTestProducer) Close() error { return nil }

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
