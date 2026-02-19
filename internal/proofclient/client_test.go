package proofclient

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
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
		Value: []byte(`{"version":"proof.fulfillment.v1","job_id":"` + jobID.Hex() + `","seal":"0x99","journal":"0x0102","metadata":{"provider":"boundless"}}`),
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
