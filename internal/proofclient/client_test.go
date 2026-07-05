package proofclient

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/dlq"
	"github.com/juno-intents/intents-juno/internal/queue"
)

type fakeProducer struct {
	topic   string
	payload []byte
	err     error
}

func (p *fakeProducer) Publish(_ context.Context, topic string, payload []byte) error {
	p.topic = topic
	p.payload = append([]byte(nil), payload...)
	return p.err
}

func (p *fakeProducer) Close() error { return nil }

type channelProducer struct {
	published chan publishedRequest
}

type publishedRequest struct {
	topic   string
	payload []byte
}

func (p *channelProducer) Publish(ctx context.Context, topic string, payload []byte) error {
	select {
	case p.published <- publishedRequest{topic: topic, payload: append([]byte(nil), payload...)}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *channelProducer) Close() error { return nil }

type fakeConsumer struct {
	msgCh chan queue.Message
	errCh chan error
}

func (c *fakeConsumer) Messages() <-chan queue.Message { return c.msgCh }
func (c *fakeConsumer) Errors() <-chan error           { return c.errCh }
func (c *fakeConsumer) Close() error {
	close(c.msgCh)
	close(c.errCh)
	return nil
}

type fakeDLQStore struct {
	proofs []dlq.ProofDLQRecord
	err    error
}

func (s *fakeDLQStore) EnsureSchema(context.Context) error { return nil }

func (s *fakeDLQStore) InsertProofDLQ(_ context.Context, rec dlq.ProofDLQRecord) error {
	if s.err != nil {
		return s.err
	}
	s.proofs = append(s.proofs, rec)
	return nil
}

func (s *fakeDLQStore) InsertDepositBatchDLQ(context.Context, dlq.DepositBatchDLQRecord) error {
	return nil
}

func (s *fakeDLQStore) InsertWithdrawalBatchDLQ(context.Context, dlq.WithdrawalBatchDLQRecord) error {
	return nil
}

func (s *fakeDLQStore) ListProofDLQ(context.Context, dlq.DLQFilter) ([]dlq.ProofDLQRecord, error) {
	return append([]dlq.ProofDLQRecord(nil), s.proofs...), nil
}

func (s *fakeDLQStore) ListDepositBatchDLQ(context.Context, dlq.DLQFilter) ([]dlq.DepositBatchDLQRecord, error) {
	return nil, nil
}

func (s *fakeDLQStore) ListWithdrawalBatchDLQ(context.Context, dlq.DLQFilter) ([]dlq.WithdrawalBatchDLQRecord, error) {
	return nil, nil
}

func (s *fakeDLQStore) CountUnacknowledged(context.Context) (dlq.DLQCounts, error) {
	return dlq.DLQCounts{}, nil
}

func (s *fakeDLQStore) Acknowledge(context.Context, string, []byte) error {
	return nil
}

func TestQueueClient_RequestProofFulfillment(t *testing.T) {
	t.Parallel()

	producer := &fakeProducer{}
	consumer := &fakeConsumer{
		msgCh: make(chan queue.Message, 1),
		errCh: make(chan error, 1),
	}
	client, err := NewQueueClient(QueueConfig{
		RequestTopic: "proof.requests.v1",
		ResultTopic:  "proof.fulfillments.v1",
		FailureTopic: "proof.failures.v1",
		Producer:     producer,
		Consumer:     consumer,
	})
	if err != nil {
		t.Fatalf("NewQueueClient: %v", err)
	}

	jobID := common.HexToHash("0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98")
	consumer.msgCh <- queue.Message{
		Topic: "proof.fulfillments.v1",
		Value: []byte(`{"version":"proof.fulfillment.v1","job_id":"` + jobID.Hex() + `","seal":"0x99","journal":"0x0102","metadata":{"provider":"sp1"}}`),
	}

	res, err := client.RequestProof(context.Background(), Request{
		JobID:        jobID,
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     time.Now().UTC().Add(time.Minute),
		Priority:     1,
	})
	if err != nil {
		t.Fatalf("RequestProof: %v", err)
	}
	if producer.topic != "proof.requests.v1" {
		t.Fatalf("request topic: got %q", producer.topic)
	}
	if len(res.Seal) != 1 || res.Seal[0] != 0x99 {
		t.Fatalf("seal mismatch: %x", res.Seal)
	}
	if len(res.Journal) != 2 || res.Journal[0] != 0x01 || res.Journal[1] != 0x02 {
		t.Fatalf("journal mismatch: %x", res.Journal)
	}
}

func TestQueueClient_RequestProofIncludesResponseGroup(t *testing.T) {
	t.Parallel()

	producer := &fakeProducer{}
	consumer := &fakeConsumer{
		msgCh: make(chan queue.Message, 1),
		errCh: make(chan error, 1),
	}
	client, err := NewQueueClient(QueueConfig{
		RequestTopic:  "proof.requests.v1",
		ResultTopic:   "proof.fulfillments.v1",
		FailureTopic:  "proof.failures.v1",
		ResponseGroup: "  ip-10-92-1-179-deposit-relayer-proof  ",
		Producer:      producer,
		Consumer:      consumer,
	})
	if err != nil {
		t.Fatalf("NewQueueClient: %v", err)
	}

	jobID := common.HexToHash("0x6a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98")
	consumer.msgCh <- queue.Message{
		Topic: "proof.fulfillments.v1",
		Value: []byte(`{"version":"proof.fulfillment.v1","job_id":"` + jobID.Hex() + `","seal":"0x99","journal":"0x0102"}`),
	}

	_, err = client.RequestProof(context.Background(), Request{
		JobID:        jobID,
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     time.Now().UTC().Add(time.Minute),
		Priority:     1,
	})
	if err != nil {
		t.Fatalf("RequestProof: %v", err)
	}

	var payload struct {
		ResponseGroup string `json:"response_group"`
	}
	if err := json.Unmarshal(producer.payload, &payload); err != nil {
		t.Fatalf("decode request payload: %v", err)
	}
	if got, want := payload.ResponseGroup, "ip-10-92-1-179-deposit-relayer-proof"; got != want {
		t.Fatalf("response group: got %q want %q", got, want)
	}
}

func TestQueueClient_RequestProofSerializesSharedResponseConsumer(t *testing.T) {
	t.Parallel()

	producer := &channelProducer{published: make(chan publishedRequest, 2)}
	consumer := &fakeConsumer{
		msgCh: make(chan queue.Message, 2),
		errCh: make(chan error, 1),
	}
	client, err := NewQueueClient(QueueConfig{
		RequestTopic:  "proof.requests.v1",
		ResultTopic:   "proof.fulfillments.v1",
		FailureTopic:  "proof.failures.v1",
		ResponseGroup: "deposit-relayer-proof",
		Producer:      producer,
		Consumer:      consumer,
	})
	if err != nil {
		t.Fatalf("NewQueueClient: %v", err)
	}

	jobA := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	jobB := common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	doneA := make(chan error, 1)
	go func() {
		_, err := client.RequestProof(ctx, validProofRequest(jobA))
		doneA <- err
	}()
	first := readPublishedRequest(t, producer.published)
	if got, want := publishedJobID(t, first.payload), jobA.Hex(); got != want {
		t.Fatalf("first published job_id = %q, want %q", got, want)
	}

	doneB := make(chan error, 1)
	go func() {
		_, err := client.RequestProof(ctx, validProofRequest(jobB))
		doneB <- err
	}()
	assertNoPublishedRequest(t, producer.published, 50*time.Millisecond)

	consumer.msgCh <- fulfillmentMessage(jobA)
	if err := readRequestProofError(t, doneA); err != nil {
		t.Fatalf("request A error: %v", err)
	}

	second := readPublishedRequest(t, producer.published)
	if got, want := publishedJobID(t, second.payload), jobB.Hex(); got != want {
		t.Fatalf("second published job_id = %q, want %q", got, want)
	}
	consumer.msgCh <- fulfillmentMessage(jobB)
	if err := readRequestProofError(t, doneB); err != nil {
		t.Fatalf("request B error: %v", err)
	}
}

func TestQueueClient_RequestProofWaitForSharedConsumerSlotHonorsContext(t *testing.T) {
	t.Parallel()

	producer := &channelProducer{published: make(chan publishedRequest, 2)}
	consumer := &fakeConsumer{
		msgCh: make(chan queue.Message, 2),
		errCh: make(chan error, 1),
	}
	client, err := NewQueueClient(QueueConfig{
		RequestTopic:  "proof.requests.v1",
		ResultTopic:   "proof.fulfillments.v1",
		FailureTopic:  "proof.failures.v1",
		ResponseGroup: "deposit-relayer-proof",
		Producer:      producer,
		Consumer:      consumer,
	})
	if err != nil {
		t.Fatalf("NewQueueClient: %v", err)
	}

	jobA := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	jobB := common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	ctxA, cancelA := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelA()

	doneA := make(chan error, 1)
	go func() {
		_, err := client.RequestProof(ctxA, validProofRequest(jobA))
		doneA <- err
	}()
	defer func() {
		consumer.msgCh <- fulfillmentMessage(jobA)
		_ = readRequestProofError(t, doneA)
	}()
	first := readPublishedRequest(t, producer.published)
	if got, want := publishedJobID(t, first.payload), jobA.Hex(); got != want {
		t.Fatalf("first published job_id = %q, want %q", got, want)
	}

	ctxB, cancelB := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelB()
	doneB := make(chan error, 1)
	go func() {
		_, err := client.RequestProof(ctxB, validProofRequest(jobB))
		doneB <- err
	}()

	select {
	case err := <-doneB:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("request B error = %v, want deadline exceeded", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timeout waiting for queued RequestProof to honor context deadline")
	}
	assertNoPublishedRequest(t, producer.published, 50*time.Millisecond)
}

func validProofRequest(jobID common.Hash) Request {
	return Request{
		JobID:        jobID,
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     time.Now().UTC().Add(time.Minute),
		Priority:     1,
	}
}

func fulfillmentMessage(jobID common.Hash) queue.Message {
	return queue.Message{
		Topic: "proof.fulfillments.v1",
		Value: []byte(`{"version":"proof.fulfillment.v1","job_id":"` + jobID.Hex() + `","seal":"0x99","journal":"0x0102"}`),
	}
}

func readPublishedRequest(t *testing.T, published <-chan publishedRequest) publishedRequest {
	t.Helper()

	select {
	case req := <-published:
		return req
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for published request")
		return publishedRequest{}
	}
}

func assertNoPublishedRequest(t *testing.T, published <-chan publishedRequest, wait time.Duration) {
	t.Helper()

	select {
	case req := <-published:
		t.Fatalf("unexpected published request before prior request completed: topic=%s job_id=%s", req.topic, publishedJobID(t, req.payload))
	case <-time.After(wait):
	}
}

func publishedJobID(t *testing.T, payload []byte) string {
	t.Helper()

	var req struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		t.Fatalf("decode published request: %v", err)
	}
	return req.JobID
}

func readRequestProofError(t *testing.T, done <-chan error) error {
	t.Helper()

	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for RequestProof")
		return nil
	}
}

func TestQueueClient_RequestProofFailure(t *testing.T) {
	t.Parallel()

	producer := &fakeProducer{}
	consumer := &fakeConsumer{
		msgCh: make(chan queue.Message, 1),
		errCh: make(chan error, 1),
	}
	client, err := NewQueueClient(QueueConfig{
		RequestTopic: "proof.requests.v1",
		ResultTopic:  "proof.fulfillments.v1",
		FailureTopic: "proof.failures.v1",
		Producer:     producer,
		Consumer:     consumer,
	})
	if err != nil {
		t.Fatalf("NewQueueClient: %v", err)
	}

	jobID := common.HexToHash("0x4314e7904fd1808ad5a2394a4e8e6cf6ccf8802f27195be7d87da01f5c23a1ee")
	consumer.msgCh <- queue.Message{
		Topic: "proof.failures.v1",
		Value: []byte(`{"version":"proof.failure.v1","job_id":"` + jobID.Hex() + `","error_code":"timeout","retryable":true,"message":"timed out"}`),
	}

	_, err = client.RequestProof(context.Background(), Request{
		JobID:        jobID,
		Pipeline:     "withdraw",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa02"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     time.Now().UTC().Add(time.Minute),
		Priority:     2,
	})
	var fail *FailureError
	if !errors.As(err, &fail) {
		t.Fatalf("expected FailureError, got %v", err)
	}
	if fail.Code != "timeout" || !fail.Retryable {
		t.Fatalf("unexpected failure: %+v", fail)
	}
}

func TestQueueClient_RequestProofIgnoresStaleFailureMessage(t *testing.T) {
	t.Parallel()

	producer := &fakeProducer{}
	consumer := &fakeConsumer{
		msgCh: make(chan queue.Message, 2),
		errCh: make(chan error, 1),
	}
	client, err := NewQueueClient(QueueConfig{
		RequestTopic: "proof.requests.v1",
		ResultTopic:  "proof.fulfillments.v1",
		FailureTopic: "proof.failures.v1",
		Producer:     producer,
		Consumer:     consumer,
	})
	if err != nil {
		t.Fatalf("NewQueueClient: %v", err)
	}

	jobID := common.HexToHash("0x9f5adf65a45f0a9dcc4ba85db2ac4d1be2a1d3d6c9db22a3a3885ad250ab3cf3")
	consumer.msgCh <- queue.Message{
		Topic:     "proof.failures.v1",
		Timestamp: time.Now().UTC().Add(-10 * time.Minute),
		Value:     []byte(`{"version":"proof.failure.v1","job_id":"` + jobID.Hex() + `","error_code":"timeout","retryable":true,"message":"stale timeout"}`),
	}
	consumer.msgCh <- queue.Message{
		Topic:     "proof.fulfillments.v1",
		Timestamp: time.Now().UTC(),
		Value:     []byte(`{"version":"proof.fulfillment.v1","job_id":"` + jobID.Hex() + `","seal":"0x99","journal":"0x0102","metadata":{"provider":"sp1"}}`),
	}

	res, err := client.RequestProof(context.Background(), Request{
		JobID:        jobID,
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     time.Now().UTC().Add(time.Minute),
		Priority:     1,
	})
	if err != nil {
		t.Fatalf("RequestProof: %v", err)
	}
	if len(res.Seal) != 1 || res.Seal[0] != 0x99 {
		t.Fatalf("seal mismatch: %x", res.Seal)
	}
}

func TestQueueClient_RequestProofFulfillmentRejectsInvalidJournal(t *testing.T) {
	t.Parallel()

	producer := &fakeProducer{}
	consumer := &fakeConsumer{
		msgCh: make(chan queue.Message, 1),
		errCh: make(chan error, 1),
	}
	client, err := NewQueueClient(QueueConfig{
		RequestTopic: "proof.requests.v1",
		ResultTopic:  "proof.fulfillments.v1",
		FailureTopic: "proof.failures.v1",
		Producer:     producer,
		Consumer:     consumer,
	})
	if err != nil {
		t.Fatalf("NewQueueClient: %v", err)
	}

	jobID := common.HexToHash("0x4314e7904fd1808ad5a2394a4e8e6cf6ccf8802f27195be7d87da01f5c23a1ee")
	consumer.msgCh <- queue.Message{
		Topic: "proof.fulfillments.v1",
		Value: []byte(`{"version":"proof.fulfillment.v1","job_id":"` + jobID.Hex() + `","seal":"0x99","journal":"zz"}`),
	}

	_, err = client.RequestProof(context.Background(), Request{
		JobID:        jobID,
		Pipeline:     "withdraw",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa02"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     time.Now().UTC().Add(time.Minute),
		Priority:     2,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "decode fulfillment journal") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestQueueClient_RequestProofFulfillmentRejectsMissingJournal(t *testing.T) {
	t.Parallel()

	producer := &fakeProducer{}
	consumer := &fakeConsumer{
		msgCh: make(chan queue.Message, 1),
		errCh: make(chan error, 1),
	}
	client, err := NewQueueClient(QueueConfig{
		RequestTopic: "proof.requests.v1",
		ResultTopic:  "proof.fulfillments.v1",
		FailureTopic: "proof.failures.v1",
		Producer:     producer,
		Consumer:     consumer,
	})
	if err != nil {
		t.Fatalf("NewQueueClient: %v", err)
	}

	jobID := common.HexToHash("0x4314e7904fd1808ad5a2394a4e8e6cf6ccf8802f27195be7d87da01f5c23a1ee")
	consumer.msgCh <- queue.Message{
		Topic: "proof.fulfillments.v1",
		Value: []byte(`{"version":"proof.fulfillment.v1","job_id":"` + jobID.Hex() + `","seal":"0x99"}`),
	}

	_, err = client.RequestProof(context.Background(), Request{
		JobID:        jobID,
		Pipeline:     "withdraw",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa02"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     time.Now().UTC().Add(time.Minute),
		Priority:     2,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "missing fulfillment journal") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestQueueClient_RequestProofRoutesMalformedResponseToDLQ(t *testing.T) {
	t.Parallel()

	producer := &fakeProducer{}
	consumer := &fakeConsumer{
		msgCh: make(chan queue.Message, 2),
		errCh: make(chan error, 1),
	}
	dlqStore := &fakeDLQStore{}
	client, err := NewQueueClient(QueueConfig{
		RequestTopic: "proof.requests.v1",
		ResultTopic:  "proof.fulfillments.v1",
		FailureTopic: "proof.failures.v1",
		Producer:     producer,
		Consumer:     consumer,
		DLQStore:     dlqStore,
		Now: func() time.Time {
			return time.Unix(1700000000, 0).UTC()
		},
	})
	if err != nil {
		t.Fatalf("NewQueueClient: %v", err)
	}

	jobID := common.HexToHash("0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98")
	consumer.msgCh <- queue.Message{
		Topic: "proof.fulfillments.v1",
		Value: []byte(`{not-json`),
	}
	consumer.msgCh <- queue.Message{
		Topic: "proof.fulfillments.v1",
		Value: []byte(`{"version":"proof.fulfillment.v1","job_id":"` + jobID.Hex() + `","seal":"0x99","journal":"0x0102","metadata":{"provider":"sp1"}}`),
	}

	res, err := client.RequestProof(context.Background(), Request{
		JobID:        jobID,
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     time.Now().UTC().Add(time.Minute),
		Priority:     1,
	})
	if err != nil {
		t.Fatalf("RequestProof: %v", err)
	}
	if len(res.Seal) != 1 || res.Seal[0] != 0x99 {
		t.Fatalf("seal mismatch: %x", res.Seal)
	}
	if len(dlqStore.proofs) != 1 {
		t.Fatalf("expected 1 DLQ record, got %d", len(dlqStore.proofs))
	}
	if dlqStore.proofs[0].ErrorCode != "malformed_response" {
		t.Fatalf("ErrorCode: got %q want %q", dlqStore.proofs[0].ErrorCode, "malformed_response")
	}
	if string(dlqStore.proofs[0].JobPayload) != `{not-json` {
		t.Fatalf("JobPayload: got %q", string(dlqStore.proofs[0].JobPayload))
	}
}

func TestQueueClient_RequestProofIgnoresUnexpectedJobIDWithoutDLQ(t *testing.T) {
	t.Parallel()

	producer := &fakeProducer{}
	consumer := &fakeConsumer{
		msgCh: make(chan queue.Message, 2),
		errCh: make(chan error, 1),
	}
	dlqStore := &fakeDLQStore{}
	client, err := NewQueueClient(QueueConfig{
		RequestTopic: "proof.requests.v1",
		ResultTopic:  "proof.fulfillments.v1",
		FailureTopic: "proof.failures.v1",
		Producer:     producer,
		Consumer:     consumer,
		DLQStore:     dlqStore,
		Now:          time.Now,
	})
	if err != nil {
		t.Fatalf("NewQueueClient: %v", err)
	}

	jobID := common.HexToHash("0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98")
	otherJobID := common.HexToHash("0x4314e7904fd1808ad5a2394a4e8e6cf6ccf8802f27195be7d87da01f5c23a1ee")
	consumer.msgCh <- queue.Message{
		Topic: "proof.fulfillments.v1",
		Value: []byte(`{"version":"proof.fulfillment.v1","job_id":"` + otherJobID.Hex() + `","seal":"0x99","journal":"0x0102"}`),
	}
	consumer.msgCh <- queue.Message{
		Topic: "proof.fulfillments.v1",
		Value: []byte(`{"version":"proof.fulfillment.v1","job_id":"` + jobID.Hex() + `","seal":"0xaa","journal":"0x0102","metadata":{"provider":"sp1"}}`),
	}

	res, err := client.RequestProof(context.Background(), Request{
		JobID:        jobID,
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     time.Now().UTC().Add(time.Minute),
		Priority:     1,
	})
	if err != nil {
		t.Fatalf("RequestProof: %v", err)
	}
	if len(res.Seal) != 1 || res.Seal[0] != 0xaa {
		t.Fatalf("seal mismatch: %x", res.Seal)
	}
	if len(dlqStore.proofs) != 0 {
		t.Fatalf("expected no DLQ records, got %d", len(dlqStore.proofs))
	}
}

func TestQueueClient_RequestProofReturnsDLQInsertionError(t *testing.T) {
	t.Parallel()

	producer := &fakeProducer{}
	consumer := &fakeConsumer{
		msgCh: make(chan queue.Message, 1),
		errCh: make(chan error, 1),
	}
	client, err := NewQueueClient(QueueConfig{
		RequestTopic: "proof.requests.v1",
		ResultTopic:  "proof.fulfillments.v1",
		FailureTopic: "proof.failures.v1",
		Producer:     producer,
		Consumer:     consumer,
		DLQStore:     &fakeDLQStore{err: errors.New("dlq unavailable")},
		Now:          time.Now,
	})
	if err != nil {
		t.Fatalf("NewQueueClient: %v", err)
	}

	jobID := common.HexToHash("0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98")
	consumer.msgCh <- queue.Message{
		Topic: "proof.fulfillments.v1",
		Value: []byte(`{not-json`),
	}

	_, err = client.RequestProof(context.Background(), Request{
		JobID:        jobID,
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     time.Now().UTC().Add(time.Minute),
		Priority:     1,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "route response to dlq") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestQueueClient_RequestProofDLQsMalformedResponseBeforeAck(t *testing.T) {
	t.Parallel()

	producer := &fakeProducer{}
	consumer := &fakeConsumer{
		msgCh: make(chan queue.Message, 2),
		errCh: make(chan error, 1),
	}
	dlqStore := dlq.NewMemoryStore(nil)
	client, err := NewQueueClient(QueueConfig{
		RequestTopic: "proof.requests.v1",
		ResultTopic:  "proof.fulfillments.v1",
		FailureTopic: "proof.failures.v1",
		Producer:     producer,
		Consumer:     consumer,
		DLQStore:     dlqStore,
	})
	if err != nil {
		t.Fatalf("NewQueueClient: %v", err)
	}

	jobID := common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	consumer.msgCh <- queue.Message{
		Topic: "proof.fulfillments.v1",
		Value: []byte(`{"version":"proof.fulfillment.v1","job_id":"` + jobID.Hex() + `","seal":"0x99","journal":"zz"}`),
	}

	_, err = client.RequestProof(context.Background(), Request{
		JobID:        jobID,
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     time.Now().UTC().Add(time.Minute),
		Priority:     1,
	})
	if err == nil {
		t.Fatal("expected error")
	}

	recs, err := dlqStore.ListProofDLQ(context.Background(), dlq.DLQFilter{})
	if err != nil {
		t.Fatalf("ListProofDLQ: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 dlq record, got %d", len(recs))
	}
	if recs[0].ErrorCode != "malformed_response" {
		t.Fatalf("ErrorCode = %q, want malformed_response", recs[0].ErrorCode)
	}
	if !strings.Contains(recs[0].ErrorMessage, "decode fulfillment journal") {
		t.Fatalf("ErrorMessage = %q", recs[0].ErrorMessage)
	}
	if got := string(recs[0].JobPayload); got == "" {
		t.Fatal("expected raw payload in dlq record")
	}
}

func TestQueueClient_RequestProofIgnoresUnmatchedResponseBeforeAck(t *testing.T) {
	t.Parallel()

	producer := &fakeProducer{}
	consumer := &fakeConsumer{
		msgCh: make(chan queue.Message, 2),
		errCh: make(chan error, 1),
	}
	dlqStore := dlq.NewMemoryStore(nil)
	client, err := NewQueueClient(QueueConfig{
		RequestTopic: "proof.requests.v1",
		ResultTopic:  "proof.fulfillments.v1",
		FailureTopic: "proof.failures.v1",
		Producer:     producer,
		Consumer:     consumer,
		DLQStore:     dlqStore,
	})
	if err != nil {
		t.Fatalf("NewQueueClient: %v", err)
	}

	jobID := common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	otherJobID := common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333")
	consumer.msgCh <- queue.Message{
		Topic: "proof.fulfillments.v1",
		Value: []byte(`{"version":"proof.fulfillment.v1","job_id":"` + otherJobID.Hex() + `","seal":"0x10","journal":"0x20"}`),
	}
	consumer.msgCh <- queue.Message{
		Topic: "proof.fulfillments.v1",
		Value: []byte(`{"version":"proof.fulfillment.v1","job_id":"` + jobID.Hex() + `","seal":"0x99","journal":"0x0102"}`),
	}

	res, err := client.RequestProof(context.Background(), Request{
		JobID:        jobID,
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     time.Now().UTC().Add(time.Minute),
		Priority:     1,
	})
	if err != nil {
		t.Fatalf("RequestProof: %v", err)
	}
	if len(res.Seal) != 1 || res.Seal[0] != 0x99 {
		t.Fatalf("seal mismatch: %x", res.Seal)
	}

	recs, err := dlqStore.ListProofDLQ(context.Background(), dlq.DLQFilter{})
	if err != nil {
		t.Fatalf("ListProofDLQ: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("expected no dlq records, got %d", len(recs))
	}
}

func TestParseResponseJobID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  common.Hash
		ok    bool
	}{
		{
			name:  "valid",
			input: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			want:  common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			ok:    true,
		},
		{name: "missing prefix", input: strings.Repeat("a", 64)},
		{name: "wrong length", input: "0x1234"},
		{name: "invalid hex", input: "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseResponseJobID(tc.input)
			if ok != tc.ok {
				t.Fatalf("ok = %t, want %t", ok, tc.ok)
			}
			if tc.ok && got != tc.want {
				t.Fatalf("hash = %s, want %s", got.Hex(), tc.want.Hex())
			}
		})
	}
}
