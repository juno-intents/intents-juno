package queue

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewConsumerValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  ConsumerConfig
	}{
		{
			name: "unsupported driver",
			cfg: ConsumerConfig{
				Driver: "unknown",
			},
		},
		{
			name: "kafka missing brokers",
			cfg: ConsumerConfig{
				Driver: DriverKafka,
				Group:  "g1",
				Topics: []string{"t1"},
			},
		},
		{
			name: "kafka missing group",
			cfg: ConsumerConfig{
				Driver:  DriverKafka,
				Brokers: []string{"127.0.0.1:9092"},
				Topics:  []string{"t1"},
			},
		},
		{
			name: "kafka missing topics",
			cfg: ConsumerConfig{
				Driver:  DriverKafka,
				Brokers: []string{"127.0.0.1:9092"},
				Group:   "g1",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			c, err := NewConsumer(ctx, tc.cfg)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if c != nil {
				t.Fatalf("expected nil consumer on error")
			}
		})
	}
}

func TestNewProducerValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  ProducerConfig
	}{
		{
			name: "unsupported driver",
			cfg:  ProducerConfig{Driver: "unknown"},
		},
		{
			name: "kafka missing brokers",
			cfg:  ProducerConfig{Driver: DriverKafka},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := NewProducer(tc.cfg)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if p != nil {
				t.Fatalf("expected nil producer on error")
			}
		})
	}
}

func TestStdioConsumerReadsLines(t *testing.T) {
	t.Parallel()

	in := strings.NewReader("first\nsecond\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c, err := NewConsumer(ctx, ConsumerConfig{
		Driver:       DriverStdio,
		Reader:       in,
		MaxLineBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}
	defer func() { _ = c.Close() }()

	var got []string
	deadline := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case m, ok := <-c.Messages():
			if !ok {
				t.Fatalf("messages channel closed early")
			}
			got = append(got, string(m.Value))
			if err := m.Ack(context.Background()); err != nil {
				t.Fatalf("Ack: %v", err)
			}
		case err := <-c.Errors():
			if err != nil {
				t.Fatalf("consumer error: %v", err)
			}
		case <-deadline:
			t.Fatalf("timeout waiting for lines")
		}
	}

	if got[0] != "first" || got[1] != "second" {
		t.Fatalf("unexpected lines: %#v", got)
	}
}

func TestStdioProducerPublishesLineDelimitedPayloads(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	p, err := NewProducer(ProducerConfig{
		Driver: DriverStdio,
		Writer: &out,
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	defer func() { _ = p.Close() }()

	if err := p.Publish(context.Background(), "unused-topic", []byte(`{"version":"v1"}`)); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if got, want := out.String(), "{\"version\":\"v1\"}\n"; got != want {
		t.Fatalf("output mismatch: got %q want %q", got, want)
	}
}

func TestMessageAckNoOp(t *testing.T) {
	t.Parallel()

	m := Message{Topic: "t1", Value: []byte("x")}
	if err := m.Ack(context.Background()); err != nil {
		t.Fatalf("Ack: %v", err)
	}
}
