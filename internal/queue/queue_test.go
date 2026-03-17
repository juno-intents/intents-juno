package queue

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
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

func TestQueueKafkaTLSEnabled(t *testing.T) {
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
		{name: "case and space", value: "  TrUe  ", want: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envKafkaTLS, tc.value)
			if got := queueKafkaTLSEnabled(); got != tc.want {
				t.Fatalf("queueKafkaTLSEnabled(%q) = %t, want %t", tc.value, got, tc.want)
			}
		})
	}
}

func TestQueueKafkaAuthMode(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{name: "unset", value: "", want: "none"},
		{name: "none", value: "none", want: "none"},
		{name: "disabled", value: "disabled", want: "none"},
		{name: "aws msk iam", value: "aws-msk-iam", want: "aws-msk-iam"},
		{name: "trim and lowercase", value: "  AWS-MSK-IAM ", want: "aws-msk-iam"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envKafkaAuthMode, tc.value)
			if got := queueKafkaAuthMode(); got != tc.want {
				t.Fatalf("queueKafkaAuthMode(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestNewProducer_RejectsInvalidKafkaAuthEnv(t *testing.T) {
	t.Setenv(envKafkaTLS, "true")
	t.Setenv(envKafkaAuthMode, "aws-msk-iam")
	t.Setenv(envKafkaAWSRegion, "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")

	p, err := NewProducer(ProducerConfig{
		Driver:  DriverKafka,
		Brokers: []string{"127.0.0.1:9092"},
	})
	if err == nil || !strings.Contains(err.Error(), envKafkaAWSRegion) {
		t.Fatalf("expected region error, got producer=%v err=%v", p, err)
	}
}

func TestNewConsumer_RejectsKafkaAuthWithoutTLS(t *testing.T) {
	t.Setenv(envKafkaTLS, "false")
	t.Setenv(envKafkaAuthMode, "aws-msk-iam")
	t.Setenv(envKafkaAWSRegion, "us-east-1")

	c, err := NewConsumer(context.Background(), ConsumerConfig{
		Driver:  DriverKafka,
		Brokers: []string{"127.0.0.1:9092"},
		Group:   "g1",
		Topics:  []string{"t1"},
	})
	if err == nil || !strings.Contains(err.Error(), envKafkaTLS) {
		t.Fatalf("expected tls error, got consumer=%v err=%v", c, err)
	}
}

func TestKafkaSASLMechanismFromEnv_UsesAWSMSKIAMV2(t *testing.T) {
	t.Setenv(envKafkaTLS, "true")
	t.Setenv(envKafkaAuthMode, "aws-msk-iam")
	t.Setenv(envKafkaAWSRegion, "us-east-1")

	originalLoader := loadAWSMSKIAMConfig
	t.Cleanup(func() {
		loadAWSMSKIAMConfig = originalLoader
	})

	loadCalled := false
	loadAWSMSKIAMConfig = func(_ context.Context, region string) (aws.Config, error) {
		loadCalled = true
		if region != "us-east-1" {
			t.Fatalf("region = %q, want us-east-1", region)
		}
		return aws.Config{
			Region: region,
			Credentials: aws.NewCredentialsCache(
				credentials.NewStaticCredentialsProvider("test-access-key", "test-secret-key", "test-session-token"),
			),
		}, nil
	}

	mech, err := kafkaSASLMechanismFromEnv()
	if err != nil {
		t.Fatalf("kafkaSASLMechanismFromEnv: %v", err)
	}
	if !loadCalled {
		t.Fatal("expected aws msk iam config loader to be called")
	}
	if mech == nil {
		t.Fatal("expected mechanism")
	}
	if got, want := mech.Name(), "AWS_MSK_IAM"; got != want {
		t.Fatalf("mechanism name = %q, want %q", got, want)
	}
}

func TestKafkaTLSConfigRequiresAtLeastTLS12WithoutCappingNewerVersions(t *testing.T) {
	t.Parallel()

	cfg := kafkaTLSConfig()
	if cfg == nil {
		t.Fatal("expected tls config")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %d, want %d", cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.MaxVersion != 0 {
		t.Fatalf("MaxVersion = %d, want 0 (uncapped)", cfg.MaxVersion)
	}
}

func TestShouldStopKafkaConsumerOnFetchError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "context canceled",
			err:  context.Canceled,
			want: true,
		},
		{
			name: "io eof",
			err:  io.EOF,
			want: false,
		},
		{
			name: "generic error",
			err:  io.ErrClosedPipe,
			want: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldStopKafkaConsumerOnFetchError(tc.err); got != tc.want {
				t.Fatalf("shouldStopKafkaConsumerOnFetchError(%v) = %t, want %t", tc.err, got, tc.want)
			}
		})
	}
}
