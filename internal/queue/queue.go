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
	"github.com/segmentio/kafka-go/sasl"
)

const (
	DriverKafka = "kafka"
	DriverStdio = "stdio"
)

const (
	envKafkaTLS          = "JUNO_QUEUE_KAFKA_TLS"
	envKafkaAuthMode     = "JUNO_QUEUE_KAFKA_AUTH_MODE"
	envKafkaAWSRegion    = "JUNO_QUEUE_KAFKA_AWS_REGION"
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

type kafkaPartitionKey struct {
	topic     string
	partition int
}

type kafkaPartitionAcks struct {
	nextOffset int64
	inflight   map[int64]kafka.Message
	acked      map[int64]struct{}
}

type kafkaAckManager struct {
	mu       sync.Mutex
	parts    map[kafkaPartitionKey]*kafkaPartitionAcks
	commitFn func(context.Context, kafka.Message) error
}

func newKafkaAckManager(commitFn func(context.Context, kafka.Message) error) *kafkaAckManager {
	return &kafkaAckManager{
		parts:    make(map[kafkaPartitionKey]*kafkaPartitionAcks),
		commitFn: commitFn,
	}
}

func (m *kafkaAckManager) Track(km kafka.Message) {
	if m == nil {
		return
	}

	key := kafkaPartitionKey{topic: km.Topic, partition: km.Partition}

	m.mu.Lock()
	defer m.mu.Unlock()

	part := m.parts[key]
	if part == nil {
		part = &kafkaPartitionAcks{
			nextOffset: km.Offset,
			inflight:   make(map[int64]kafka.Message),
			acked:      make(map[int64]struct{}),
		}
		m.parts[key] = part
	}
	if km.Offset < part.nextOffset {
		return
	}
	part.inflight[km.Offset] = km
}

func (m *kafkaAckManager) Ack(ctx context.Context, km kafka.Message) error {
	if m == nil || m.commitFn == nil {
		return nil
	}

	key := kafkaPartitionKey{topic: km.Topic, partition: km.Partition}

	m.mu.Lock()
	defer m.mu.Unlock()

	part := m.parts[key]
	if part == nil || km.Offset < part.nextOffset {
		return nil
	}
	if _, ok := part.inflight[km.Offset]; !ok {
		return nil
	}
	part.acked[km.Offset] = struct{}{}

	var (
		commitMsg        kafka.Message
		shouldCommit     bool
		committedOffsets []int64
	)
	nextOffset := part.nextOffset
	for {
		msg, ok := part.inflight[nextOffset]
		if !ok {
			break
		}
		if _, ok := part.acked[nextOffset]; !ok {
			break
		}
		commitMsg = msg
		shouldCommit = true
		committedOffsets = append(committedOffsets, nextOffset)
		nextOffset++
	}

	if !shouldCommit {
		return nil
	}
	if err := m.commitFn(ctx, commitMsg); err != nil {
		return err
	}

	for _, offset := range committedOffsets {
		delete(part.inflight, offset)
		delete(part.acked, offset)
	}
	part.nextOffset = nextOffset
	if len(part.inflight) == 0 && len(part.acked) == 0 {
		delete(m.parts, key)
	}
	return nil
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

	// KafkaLogger, if non-nil, receives internal kafka-go reader logs (group joins, rebalances, fetches).
	KafkaLogger kafka.Logger

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

func kafkaTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

func queueKafkaAuthMode() string {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(envKafkaAuthMode)))
	switch v {
	case "", "none", "disabled":
		return "none"
	default:
		return v
	}
}

func queueKafkaAWSRegion() string {
	for _, key := range []string{envKafkaAWSRegion, "AWS_REGION", "AWS_DEFAULT_REGION"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return ""
}

func kafkaSASLMechanismFromEnv() (sasl.Mechanism, error) {
	switch mode := queueKafkaAuthMode(); mode {
	case "none":
		return nil, nil
	case "aws-msk-iam":
		if !queueKafkaTLSEnabled() {
			return nil, errors.New("kafka aws-msk-iam auth requires JUNO_QUEUE_KAFKA_TLS=true")
		}
		region := queueKafkaAWSRegion()
		if region == "" {
			return nil, errors.New("kafka aws-msk-iam auth requires JUNO_QUEUE_KAFKA_AWS_REGION or AWS_REGION")
		}
		return newAWSMSKIAMMechanism(region)
	default:
		return nil, fmt.Errorf("unsupported kafka auth mode %q", mode)
	}
}

func kafkaDialerFromEnv(timeout time.Duration) (*kafka.Dialer, error) {
	mechanism, err := kafkaSASLMechanismFromEnv()
	if err != nil {
		return nil, err
	}
	dialer := &kafka.Dialer{Timeout: timeout}
	if queueKafkaTLSEnabled() {
		dialer.TLS = kafkaTLSConfig()
	}
	if mechanism != nil {
		dialer.SASLMechanism = mechanism
	}
	return dialer, nil
}

func kafkaTransportFromEnv() (*kafka.Transport, error) {
	mechanism, err := kafkaSASLMechanismFromEnv()
	if err != nil {
		return nil, err
	}
	transport := &kafka.Transport{}
	if queueKafkaTLSEnabled() {
		transport.TLS = kafkaTLSConfig()
	}
	if mechanism != nil {
		transport.SASL = mechanism
	}
	return transport, nil
}

// NewKafkaDialerFromEnv returns a kafka-go dialer configured from the queue transport env vars.
func NewKafkaDialerFromEnv(timeout time.Duration) (*kafka.Dialer, error) {
	return kafkaDialerFromEnv(timeout)
}

// NewKafkaTransportFromEnv returns a kafka-go transport configured from the queue transport env vars.
func NewKafkaTransportFromEnv() (*kafka.Transport, error) {
	return kafkaTransportFromEnv()
}

type kafkaAdminClient interface {
	Metadata(ctx context.Context, req *kafka.MetadataRequest) (*kafka.MetadataResponse, error)
	CreateTopics(ctx context.Context, req *kafka.CreateTopicsRequest) (*kafka.CreateTopicsResponse, error)
}

var newKafkaAdminClient = func(broker string, timeout time.Duration) (kafkaAdminClient, error) {
	transport, err := NewKafkaTransportFromEnv()
	if err != nil {
		return nil, err
	}
	return &kafka.Client{
		Addr:      kafka.TCP(broker),
		Timeout:   timeout,
		Transport: transport,
	}, nil
}

// EnsureKafkaTopics creates missing Kafka topics before services begin producing
// or consuming. It is a no-op for empty topic lists.
func EnsureKafkaTopics(ctx context.Context, brokers []string, topics []string) error {
	return ensureKafkaTopicsWithFactory(ctx, brokers, topics, newKafkaAdminClient)
}

func ensureKafkaTopicsWithFactory(
	ctx context.Context,
	brokers []string,
	topics []string,
	clientFactory func(string, time.Duration) (kafkaAdminClient, error),
) error {
	brokers = normalizeList(brokers)
	if len(brokers) == 0 {
		return errors.New("kafka topic creation requires at least one broker")
	}
	topics = normalizeDedupedList(topics)
	if len(topics) == 0 {
		return nil
	}

	var lastErr error
	for _, broker := range brokers {
		client, err := clientFactory(broker, 10*time.Second)
		if err != nil {
			lastErr = fmt.Errorf("new admin client for %s: %w", broker, err)
			continue
		}

		inspectCtx, inspectCancel := context.WithTimeout(ctx, 15*time.Second)
		missingTopics, err := kafkaTopicsMissing(inspectCtx, client, topics)
		inspectCancel()
		if err != nil {
			lastErr = fmt.Errorf("metadata topics via %s: %w", broker, err)
			continue
		}
		if len(missingTopics) == 0 {
			return nil
		}

		createReq := &kafka.CreateTopicsRequest{
			Addr:   kafka.TCP(broker),
			Topics: make([]kafka.TopicConfig, len(missingTopics)),
		}
		for i, topic := range missingTopics {
			createReq.Topics[i] = kafka.TopicConfig{
				Topic:             topic,
				NumPartitions:     -1,
				ReplicationFactor: -1,
			}
		}

		createCtx, createCancel := context.WithTimeout(ctx, 15*time.Second)
		createResp, err := client.CreateTopics(createCtx, createReq)
		createCancel()
		if err != nil {
			lastErr = fmt.Errorf("create topics via %s: %w", broker, err)
			continue
		}
		if createResp != nil {
			failedTopics := make([]string, 0)
			for _, topic := range missingTopics {
				if topicErr := createResp.Errors[topic]; topicErr != nil && !isTopicAlreadyExistsError(topicErr) {
					failedTopics = append(failedTopics, fmt.Sprintf("%s: %v", topic, topicErr))
				}
			}
			if len(failedTopics) > 0 {
				lastErr = fmt.Errorf("create topics via %s: %s", broker, strings.Join(failedTopics, "; "))
				continue
			}
		}

		verifyCtx, verifyCancel := context.WithTimeout(ctx, 15*time.Second)
		err = runWithRetry(verifyCtx, time.Second, func(stepCtx context.Context) error {
			stillMissing, err := kafkaTopicsMissing(stepCtx, client, topics)
			if err != nil {
				return err
			}
			if len(stillMissing) > 0 {
				return fmt.Errorf("missing %s", strings.Join(stillMissing, ", "))
			}
			return nil
		})
		verifyCancel()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("verify topics via %s: %w", broker, err)
	}

	if lastErr == nil {
		lastErr = errors.New("unable to create kafka topics")
	}
	return lastErr
}

func kafkaTopicsMissing(ctx context.Context, client kafkaAdminClient, topics []string) ([]string, error) {
	topics = normalizeDedupedList(topics)
	if len(topics) == 0 {
		return nil, nil
	}
	meta, err := client.Metadata(ctx, &kafka.MetadataRequest{Topics: topics})
	if err != nil {
		return nil, err
	}
	metadataByTopic := make(map[string]kafka.Topic, len(meta.Topics))
	for _, topicMeta := range meta.Topics {
		metadataByTopic[topicMeta.Name] = topicMeta
	}
	missing := make([]string, 0)
	for _, topic := range topics {
		topicMeta, ok := metadataByTopic[topic]
		if !ok {
			missing = append(missing, topic)
			continue
		}
		if topicMeta.Error != nil {
			if errors.Is(topicMeta.Error, kafka.UnknownTopicOrPartition) {
				missing = append(missing, topic)
				continue
			}
			return nil, topicMeta.Error
		}
		if len(topicMeta.Partitions) == 0 {
			missing = append(missing, topic)
		}
	}
	return missing, nil
}

func isTopicAlreadyExistsError(err error) bool {
	var kafkaErr kafka.Error
	return errors.As(err, &kafkaErr) && kafkaErr == kafka.TopicAlreadyExists
}

func normalizeDedupedList(values []string) []string {
	values = normalizeList(values)
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func runWithRetry(ctx context.Context, interval time.Duration, fn func(context.Context) error) error {
	if interval <= 0 {
		interval = 2 * time.Second
	}

	var lastErr error
	for {
		if err := fn(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			if lastErr == nil {
				return ctx.Err()
			}
			return fmt.Errorf("%w (last error: %v)", ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
}

type kafkaConsumer struct {
	reader *kafka.Reader

	msgCh chan Message
	errCh chan error

	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
	acks   *kafkaAckManager
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
		Brokers:               brokers,
		GroupID:               strings.TrimSpace(cfg.Group),
		GroupTopics:           topics,
		MinBytes:              minBytes,
		MaxBytes:              maxBytes,
		StartOffset:           kafka.FirstOffset,
		WatchPartitionChanges: true,
	}
	dialer, err := kafkaDialerFromEnv(10 * time.Second)
	if err != nil {
		return nil, err
	}
	readerCfg.Dialer = dialer
	if cfg.KafkaLogger != nil {
		readerCfg.Logger = cfg.KafkaLogger
		readerCfg.ErrorLogger = cfg.KafkaLogger
	}
	reader := kafka.NewReader(readerCfg)
	ctx, cancel := context.WithCancel(parent)
	c := &kafkaConsumer{
		reader: reader,
		msgCh:  make(chan Message, 64),
		errCh:  make(chan error, 8),
		cancel: cancel,
		done:   make(chan struct{}),
		acks: newKafkaAckManager(func(ackCtx context.Context, km kafka.Message) error {
			return reader.CommitMessages(ackCtx, km)
		}),
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
		c.acks.Track(km)

		msg := Message{
			Topic:     km.Topic,
			Key:       append([]byte(nil), km.Key...),
			Value:     append([]byte(nil), km.Value...),
			Timestamp: km.Time,
			ackFn: func(ackCtx context.Context) error {
				return c.acks.Ack(ackCtx, km)
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
	transport, err := kafkaTransportFromEnv()
	if err != nil {
		return nil, err
	}
	writer.Transport = transport

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
