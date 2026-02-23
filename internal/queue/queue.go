package queue

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
)

const (
	DriverKafka = "kafka"
	DriverStdio = "stdio"
)

const (
	envKafkaTLS          = "JUNO_QUEUE_KAFKA_TLS"
	defaultMaxLineBytes  = 1 << 20
	defaultKafkaMinBytes = 1
	defaultKafkaMaxBytes = 10 << 20
)

// Message is a queue record delivered to a consumer.
type Message struct {
	Topic string
	Key   []byte
	Value []byte
	// Timestamp is the producer timestamp (Kafka) or local receive time (stdio).
	Timestamp time.Time

	ackFn func(context.Context) error
}

// Ack commits/acknowledges message processing when required by the driver.
func (m Message) Ack(ctx context.Context) error {
	if m.ackFn == nil {
		return nil
	}
	return m.ackFn(ctx)
}

// Consumer consumes queue messages asynchronously.
type Consumer interface {
	Messages() <-chan Message
	Errors() <-chan error
	Close() error
}

// Producer publishes queue messages.
type Producer interface {
	Publish(ctx context.Context, topic string, payload []byte) error
	Close() error
}

// ConsumerConfig configures queue consumers.
type ConsumerConfig struct {
	Driver string

	// Kafka fields.
	Brokers []string
	Group   string
	Topics  []string

	KafkaMinBytes int
	KafkaMaxBytes int

	// Stdio fields.
	Reader       io.Reader
	MaxLineBytes int
}

// ProducerConfig configures queue producers.
type ProducerConfig struct {
	Driver string

	// Kafka fields.
	Brokers      []string
	BatchTimeout time.Duration

	// Stdio fields.
	Writer io.Writer
}

// NewConsumer creates a queue consumer for the configured driver.
func NewConsumer(ctx context.Context, cfg ConsumerConfig) (Consumer, error) {
	switch normalizeDriver(cfg.Driver) {
	case DriverKafka:
		return newKafkaConsumer(ctx, cfg)
	case DriverStdio:
		return newStdioConsumer(ctx, cfg)
	default:
		return nil, fmt.Errorf("unsupported queue driver %q", cfg.Driver)
	}
}

// NewProducer creates a queue producer for the configured driver.
func NewProducer(cfg ProducerConfig) (Producer, error) {
	switch normalizeDriver(cfg.Driver) {
	case DriverKafka:
		return newKafkaProducer(cfg)
	case DriverStdio:
		return newStdioProducer(cfg), nil
	default:
		return nil, fmt.Errorf("unsupported queue driver %q", cfg.Driver)
	}
}

func normalizeDriver(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return DriverKafka
	}
	return v
}

func normalizeList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func SplitCommaList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return normalizeList(strings.Split(s, ","))
}

func queueKafkaTLSEnabled() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(envKafkaTLS)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

type kafkaConsumer struct {
	reader *kafka.Reader

	msgCh chan Message
	errCh chan error

	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func shouldStopKafkaConsumerOnFetchError(err error) bool {
	return errors.Is(err, context.Canceled)
}

func newKafkaConsumer(parent context.Context, cfg ConsumerConfig) (Consumer, error) {
	brokers := normalizeList(cfg.Brokers)
	topics := normalizeList(cfg.Topics)
	if len(brokers) == 0 {
		return nil, errors.New("kafka consumer requires at least one broker")
	}
	if strings.TrimSpace(cfg.Group) == "" {
		return nil, errors.New("kafka consumer requires group")
	}
	if len(topics) == 0 {
		return nil, errors.New("kafka consumer requires at least one topic")
	}
	minBytes := cfg.KafkaMinBytes
	if minBytes <= 0 {
		minBytes = defaultKafkaMinBytes
	}
	maxBytes := cfg.KafkaMaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultKafkaMaxBytes
	}
	if maxBytes < minBytes {
		return nil, errors.New("kafka consumer max bytes must be >= min bytes")
	}

	readerCfg := kafka.ReaderConfig{
		Brokers:     brokers,
		GroupID:     strings.TrimSpace(cfg.Group),
		GroupTopics: topics,
		MinBytes:    minBytes,
		MaxBytes:    maxBytes,
	}
	if queueKafkaTLSEnabled() {
		readerCfg.Dialer = &kafka.Dialer{
			Timeout: 10 * time.Second,
			TLS: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
	}
	reader := kafka.NewReader(readerCfg)
	ctx, cancel := context.WithCancel(parent)
	c := &kafkaConsumer{
		reader: reader,
		msgCh:  make(chan Message, 64),
		errCh:  make(chan error, 8),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go c.run(ctx)
	return c, nil
}

func (c *kafkaConsumer) run(ctx context.Context) {
	defer close(c.done)
	defer close(c.msgCh)
	defer close(c.errCh)

	for {
		km, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if shouldStopKafkaConsumerOnFetchError(err) {
				return
			}
			select {
			case c.errCh <- err:
			case <-ctx.Done():
				return
			}
			continue
		}

		msg := Message{
			Topic:     km.Topic,
			Key:       append([]byte(nil), km.Key...),
			Value:     append([]byte(nil), km.Value...),
			Timestamp: km.Time,
			ackFn: func(ackCtx context.Context) error {
				return c.reader.CommitMessages(ackCtx, km)
			},
		}
		select {
		case c.msgCh <- msg:
		case <-ctx.Done():
			return
		}
	}
}

func (c *kafkaConsumer) Messages() <-chan Message {
	return c.msgCh
}

func (c *kafkaConsumer) Errors() <-chan error {
	return c.errCh
}

func (c *kafkaConsumer) Close() error {
	var err error
	c.once.Do(func() {
		c.cancel()
		err = c.reader.Close()
		<-c.done
	})
	return err
}

type stdioConsumer struct {
	msgCh chan Message
	errCh chan error

	cancel context.CancelFunc
	once   sync.Once
}

func newStdioConsumer(parent context.Context, cfg ConsumerConfig) (Consumer, error) {
	reader := cfg.Reader
	if reader == nil {
		reader = os.Stdin
	}
	maxLineBytes := cfg.MaxLineBytes
	if maxLineBytes <= 0 {
		maxLineBytes = defaultMaxLineBytes
	}

	ctx, cancel := context.WithCancel(parent)
	c := &stdioConsumer{
		msgCh:  make(chan Message, 64),
		errCh:  make(chan error, 8),
		cancel: cancel,
	}
	go func() {
		defer close(c.msgCh)
		defer close(c.errCh)

		sc := bufio.NewScanner(reader)
		sc.Buffer(make([]byte, 1024), maxLineBytes)
		for sc.Scan() {
			line := append([]byte(nil), sc.Bytes()...)
			msg := Message{
				Value:     line,
				Timestamp: time.Now().UTC(),
			}
			select {
			case c.msgCh <- msg:
			case <-ctx.Done():
				return
			}
		}
		if err := sc.Err(); err != nil {
			select {
			case c.errCh <- err:
			case <-ctx.Done():
			}
		}
	}()
	return c, nil
}

func (c *stdioConsumer) Messages() <-chan Message {
	return c.msgCh
}

func (c *stdioConsumer) Errors() <-chan error {
	return c.errCh
}

func (c *stdioConsumer) Close() error {
	c.once.Do(func() {
		c.cancel()
	})
	return nil
}

type kafkaProducer struct {
	writer *kafka.Writer
}

func newKafkaProducer(cfg ProducerConfig) (Producer, error) {
	brokers := normalizeList(cfg.Brokers)
	if len(brokers) == 0 {
		return nil, errors.New("kafka producer requires at least one broker")
	}

	batchTimeout := cfg.BatchTimeout
	if batchTimeout <= 0 {
		batchTimeout = 10 * time.Millisecond
	}

	writer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		BatchTimeout: batchTimeout,
		RequiredAcks: kafka.RequireAll,
	}
	if queueKafkaTLSEnabled() {
		writer.Transport = &kafka.Transport{
			TLS: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
	}

	return &kafkaProducer{writer: writer}, nil
}

func (p *kafkaProducer) Publish(ctx context.Context, topic string, payload []byte) error {
	topic = strings.TrimSpace(topic)
	if topic == "" {
		return errors.New("topic is required")
	}
	return p.writer.WriteMessages(ctx, kafka.Message{Topic: topic, Value: payload})
}

func (p *kafkaProducer) Close() error {
	return p.writer.Close()
}

type stdioProducer struct {
	w io.Writer
	m sync.Mutex
}

func newStdioProducer(cfg ProducerConfig) Producer {
	w := cfg.Writer
	if w == nil {
		w = os.Stdout
	}
	return &stdioProducer{w: w}
}

func (p *stdioProducer) Publish(_ context.Context, _ string, payload []byte) error {
	p.m.Lock()
	defer p.m.Unlock()

	if _, err := p.w.Write(payload); err != nil {
		return err
	}
	if _, err := p.w.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}

func (p *stdioProducer) Close() error {
	return nil
}
