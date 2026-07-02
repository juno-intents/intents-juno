package queue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultPostgresLeaseDuration    = 30 * time.Second
	defaultPostgresMaterializeLimit = 100
	defaultPostgresPollInterval     = 250 * time.Millisecond
	postgresQueueSchemaAdvisoryLock = 0x4a554e4f51554555
)

var (
	errPostgresQueueStaleAck   = errors.New("postgres queue: stale or missing ack token")
	errPostgresQueueStaleLease = errors.New("postgres queue: stale or missing lease token")
)

const postgresQueueSchemaSQL = `
CREATE TABLE IF NOT EXISTS queue_topic_sequences (
	topic TEXT PRIMARY KEY,
	next_seq BIGINT NOT NULL DEFAULT 1,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT queue_topic_sequences_topic_nonempty CHECK (topic <> ''),
	CONSTRAINT queue_topic_sequences_next_seq_positive CHECK (next_seq > 0)
);

CREATE TABLE IF NOT EXISTS queue_messages (
	topic TEXT NOT NULL,
	seq BIGINT NOT NULL,
	payload BYTEA NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (topic, seq),
	CONSTRAINT queue_messages_topic_nonempty CHECK (topic <> ''),
	CONSTRAINT queue_messages_seq_positive CHECK (seq > 0)
);

CREATE TABLE IF NOT EXISTS queue_group_offsets (
	consumer_group TEXT NOT NULL,
	topic TEXT NOT NULL,
	next_seq BIGINT NOT NULL DEFAULT 1,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (consumer_group, topic),
	CONSTRAINT queue_group_offsets_group_nonempty CHECK (consumer_group <> ''),
	CONSTRAINT queue_group_offsets_topic_nonempty CHECK (topic <> ''),
	CONSTRAINT queue_group_offsets_next_seq_positive CHECK (next_seq > 0)
);

CREATE TABLE IF NOT EXISTS queue_deliveries (
	topic TEXT NOT NULL,
	seq BIGINT NOT NULL,
	consumer_group TEXT NOT NULL,
	attempt_count INTEGER NOT NULL DEFAULT 0,
	lease_owner TEXT,
	lease_expires_at TIMESTAMPTZ,
	acked_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (topic, seq, consumer_group),
	FOREIGN KEY (topic, seq) REFERENCES queue_messages(topic, seq) ON DELETE CASCADE,
	CONSTRAINT queue_deliveries_group_nonempty CHECK (consumer_group <> ''),
	CONSTRAINT queue_deliveries_attempt_nonnegative CHECK (attempt_count >= 0)
);

CREATE INDEX IF NOT EXISTS queue_messages_created_idx ON queue_messages (created_at);
CREATE INDEX IF NOT EXISTS queue_group_offsets_topic_idx ON queue_group_offsets (topic, next_seq);
CREATE INDEX IF NOT EXISTS queue_deliveries_claim_idx ON queue_deliveries (consumer_group, topic, acked_at, lease_expires_at, seq);
`

type postgresQueueRecord struct {
	topic     string
	seq       int64
	attempt   int
	owner     string
	payload   []byte
	createdAt time.Time
	claimedAt time.Time
}

type postgresQueueClaimConfig struct {
	group            string
	topics           []string
	owner            string
	initialPosition  string
	initialSequences map[string]int64
	leaseDuration    time.Duration
	materializeLimit int
	limit            int
}

type postgresQueueBackend interface {
	ensureSchema(context.Context) error
	enqueue(context.Context, string, []byte) error
	claim(context.Context, postgresQueueClaimConfig) ([]postgresQueueRecord, error)
	ack(context.Context, string, string, int64, string, int) error
	renew(context.Context, string, string, int64, string, int, time.Duration) error
	close() error
}

type postgresQueueStore struct {
	pool  *pgxpool.Pool
	owned bool
}

func newPostgresQueueStore(ctx context.Context, dsn string, pool *pgxpool.Pool) (postgresQueueBackend, error) {
	if pool != nil {
		return &postgresQueueStore{pool: pool}, nil
	}
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("postgres queue requires --postgres-dsn or a postgres pool")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres queue: connect: %w", err)
	}
	return &postgresQueueStore{pool: pool, owned: true}, nil
}

func (s *postgresQueueStore) ensureSchema(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return errors.New("postgres queue: nil store")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("postgres queue: begin schema tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(postgresQueueSchemaAdvisoryLock)); err != nil {
		return fmt.Errorf("postgres queue: lock schema migration: %w", err)
	}
	if _, err := tx.Exec(ctx, postgresQueueSchemaSQL); err != nil {
		return fmt.Errorf("postgres queue: ensure schema: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres queue: commit schema tx: %w", err)
	}
	return nil
}

func (s *postgresQueueStore) enqueue(ctx context.Context, topic string, payload []byte) error {
	if s == nil || s.pool == nil {
		return errors.New("postgres queue: nil store")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("postgres queue: begin enqueue tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := EnqueuePostgresTx(ctx, tx, topic, payload); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres queue: commit enqueue tx: %w", err)
	}
	return nil
}

// EnqueuePostgresTx appends a message to the Postgres queue inside an existing transaction.
// The caller is responsible for committing or rolling back the transaction and for ensuring
// the Postgres queue schema has already been created.
func EnqueuePostgresTx(ctx context.Context, tx pgx.Tx, topic string, payload []byte) error {
	topic = strings.TrimSpace(topic)
	if topic == "" {
		return errors.New("topic is required")
	}
	if tx == nil {
		return errors.New("postgres queue: nil transaction")
	}

	var seq int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO queue_topic_sequences (topic, next_seq, updated_at)
		VALUES ($1, 2, now())
		ON CONFLICT (topic) DO UPDATE
		SET next_seq = queue_topic_sequences.next_seq + 1,
			updated_at = now()
		RETURNING next_seq - 1
	`, topic).Scan(&seq); err != nil {
		return fmt.Errorf("postgres queue: allocate sequence: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO queue_messages (topic, seq, payload, created_at)
		VALUES ($1, $2, $3, now())
	`, topic, seq, append([]byte(nil), payload...)); err != nil {
		return fmt.Errorf("postgres queue: insert message: %w", err)
	}
	return nil
}

func (s *postgresQueueStore) claim(ctx context.Context, cfg postgresQueueClaimConfig) ([]postgresQueueRecord, error) {
	cfg.group = strings.TrimSpace(cfg.group)
	cfg.topics = normalizeDedupedList(cfg.topics)
	cfg.owner = strings.TrimSpace(cfg.owner)
	initialPosition, err := normalizePostgresInitialPosition(cfg.initialPosition)
	if err != nil {
		return nil, err
	}
	cfg.initialPosition = initialPosition
	if cfg.group == "" {
		return nil, errors.New("postgres queue consumer requires group")
	}
	if len(cfg.topics) == 0 {
		return nil, errors.New("postgres queue consumer requires at least one topic")
	}
	if cfg.owner == "" {
		return nil, errors.New("postgres queue consumer requires owner")
	}
	if cfg.leaseDuration <= 0 {
		return nil, errors.New("postgres queue lease duration must be > 0")
	}
	if cfg.limit <= 0 {
		cfg.limit = 1
	}
	if cfg.materializeLimit <= 0 {
		cfg.materializeLimit = defaultPostgresMaterializeLimit
	}
	if cfg.materializeLimit < cfg.limit {
		cfg.materializeLimit = cfg.limit
	}
	if s == nil || s.pool == nil {
		return nil, errors.New("postgres queue: nil store")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("postgres queue: begin claim tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, topic := range cfg.topics {
		initialSeq := cfg.initialSequences[topic]
		if initialSeq < 0 {
			return nil, fmt.Errorf("postgres queue: initial sequence for topic %q must be > 0", topic)
		}
		if initialSeq > 0 {
			if _, err := tx.Exec(ctx, `
				INSERT INTO queue_group_offsets (consumer_group, topic, next_seq, created_at, updated_at)
				VALUES ($1, $2, $3, now(), now())
				ON CONFLICT (consumer_group, topic) DO NOTHING
			`, cfg.group, topic, initialSeq); err != nil {
				return nil, fmt.Errorf("postgres queue: ensure explicit group offset: %w", err)
			}
			continue
		}
		if cfg.initialPosition == PostgresInitialPositionLatest {
			if _, err := tx.Exec(ctx, `
				INSERT INTO queue_group_offsets (consumer_group, topic, next_seq, created_at, updated_at)
				SELECT $1, $2, COALESCE(MAX(seq) + 1, 1), now(), now()
				FROM queue_messages
				WHERE topic = $2
				ON CONFLICT (consumer_group, topic) DO NOTHING
			`, cfg.group, topic); err != nil {
				return nil, fmt.Errorf("postgres queue: ensure latest group offset: %w", err)
			}
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO queue_group_offsets (consumer_group, topic, next_seq, created_at, updated_at)
			VALUES ($1, $2, 1, now(), now())
			ON CONFLICT (consumer_group, topic) DO NOTHING
		`, cfg.group, topic); err != nil {
			return nil, fmt.Errorf("postgres queue: ensure earliest group offset: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `
		WITH target_topics AS (
			SELECT topic, next_seq
			FROM queue_group_offsets
			WHERE consumer_group = $1
			  AND topic = ANY($2::text[])
		),
		to_materialize AS (
			SELECT m.topic, m.seq
			FROM target_topics o
			JOIN LATERAL (
				SELECT topic, seq
				FROM queue_messages
				WHERE topic = o.topic
				  AND seq >= o.next_seq
				ORDER BY seq
				LIMIT $3
			) m ON true
		)
		INSERT INTO queue_deliveries (topic, seq, consumer_group, created_at, updated_at)
		SELECT topic, seq, $1, now(), now()
		FROM to_materialize
		ON CONFLICT (topic, seq, consumer_group) DO NOTHING
	`, cfg.group, cfg.topics, cfg.materializeLimit); err != nil {
		return nil, fmt.Errorf("postgres queue: ensure deliveries: %w", err)
	}

	rows, err := tx.Query(ctx, `
		WITH claimable AS (
			SELECT d.topic, d.seq
			FROM queue_deliveries d
			WHERE d.consumer_group = $1
			  AND d.topic = ANY($2::text[])
			  AND d.acked_at IS NULL
			  AND (d.lease_expires_at IS NULL OR d.lease_expires_at <= now())
			  AND NOT EXISTS (
				  SELECT 1
				  FROM queue_deliveries prev
				  WHERE prev.consumer_group = d.consumer_group
				    AND prev.topic = d.topic
				    AND prev.seq < d.seq
				    AND prev.acked_at IS NULL
			  )
			ORDER BY d.topic, d.seq
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		),
		updated AS (
			UPDATE queue_deliveries d
			SET attempt_count = d.attempt_count + 1,
				lease_owner = $4,
				lease_expires_at = now() + ($5::bigint * interval '1 millisecond'),
				updated_at = now()
			FROM claimable c
			WHERE d.consumer_group = $1
			  AND d.topic = c.topic
			  AND d.seq = c.seq
			RETURNING d.topic, d.seq, d.attempt_count, d.lease_owner
		)
		SELECT u.topic, u.seq, u.attempt_count, u.lease_owner, m.payload, m.created_at, now()
		FROM updated u
		JOIN queue_messages m ON m.topic = u.topic AND m.seq = u.seq
		ORDER BY u.topic, u.seq
	`, cfg.group, cfg.topics, cfg.limit, cfg.owner, cfg.leaseDuration.Milliseconds())
	if err != nil {
		return nil, fmt.Errorf("postgres queue: claim messages: %w", err)
	}
	defer rows.Close()

	records := make([]postgresQueueRecord, 0)
	for rows.Next() {
		var rec postgresQueueRecord
		if err := rows.Scan(&rec.topic, &rec.seq, &rec.attempt, &rec.owner, &rec.payload, &rec.createdAt, &rec.claimedAt); err != nil {
			return nil, fmt.Errorf("postgres queue: scan claimed message: %w", err)
		}
		rec.payload = append([]byte(nil), rec.payload...)
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres queue: iterate claimed messages: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("postgres queue: commit claim tx: %w", err)
	}
	return records, nil
}

func (s *postgresQueueStore) ack(ctx context.Context, group, topic string, seq int64, owner string, attempt int) error {
	if s == nil || s.pool == nil {
		return errors.New("postgres queue: nil store")
	}
	group = strings.TrimSpace(group)
	topic = strings.TrimSpace(topic)
	owner = strings.TrimSpace(owner)
	if group == "" || topic == "" || owner == "" || seq <= 0 || attempt <= 0 {
		return errors.New("postgres queue: invalid ack token")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("postgres queue: begin ack tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		WITH locked AS MATERIALIZED (
			SELECT consumer_group, topic, seq, lease_expires_at
			FROM queue_deliveries
			WHERE consumer_group = $1
			  AND topic = $2
			  AND seq = $3
			  AND lease_owner = $4
			  AND attempt_count = $5
			  AND acked_at IS NULL
			FOR UPDATE
		)
		UPDATE queue_deliveries
		SET acked_at = COALESCE(acked_at, clock_timestamp()),
			lease_owner = NULL,
			lease_expires_at = NULL,
			updated_at = clock_timestamp()
		FROM locked
		WHERE queue_deliveries.consumer_group = locked.consumer_group
		  AND queue_deliveries.topic = locked.topic
		  AND queue_deliveries.seq = locked.seq
		  AND locked.lease_expires_at > clock_timestamp()
	`, group, topic, seq, owner, attempt)
	if err != nil {
		return fmt.Errorf("postgres queue: ack message: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w for group=%q topic=%q seq=%d", errPostgresQueueStaleAck, group, topic, seq)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE queue_group_offsets o
		SET next_seq = GREATEST(
				o.next_seq,
				COALESCE((
					SELECT MIN(m.seq)
					FROM queue_messages m
					LEFT JOIN queue_deliveries d
					  ON d.consumer_group = o.consumer_group
					 AND d.topic = m.topic
					 AND d.seq = m.seq
					WHERE m.topic = o.topic
					  AND m.seq >= o.next_seq
					  AND (d.seq IS NULL OR d.acked_at IS NULL)
				), (
					SELECT COALESCE(MAX(m.seq) + 1, o.next_seq)
					FROM queue_messages m
					WHERE m.topic = o.topic
				))
			),
			updated_at = now()
		WHERE o.consumer_group = $1
		  AND o.topic = $2
	`, group, topic); err != nil {
		return fmt.Errorf("postgres queue: advance group offset: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres queue: commit ack tx: %w", err)
	}
	return nil
}

func (s *postgresQueueStore) renew(ctx context.Context, group, topic string, seq int64, owner string, attempt int, leaseDuration time.Duration) error {
	if s == nil || s.pool == nil {
		return errors.New("postgres queue: nil store")
	}
	group = strings.TrimSpace(group)
	topic = strings.TrimSpace(topic)
	owner = strings.TrimSpace(owner)
	if group == "" || topic == "" || owner == "" || seq <= 0 || attempt <= 0 || leaseDuration <= 0 {
		return errors.New("postgres queue: invalid lease token")
	}
	tag, err := s.pool.Exec(ctx, `
		WITH locked AS MATERIALIZED (
			SELECT consumer_group, topic, seq, lease_expires_at
			FROM queue_deliveries
			WHERE consumer_group = $1
			  AND topic = $2
			  AND seq = $3
			  AND lease_owner = $4
			  AND attempt_count = $5
			  AND acked_at IS NULL
			FOR UPDATE
		)
		UPDATE queue_deliveries
		SET lease_expires_at = clock_timestamp() + ($6::bigint * interval '1 millisecond'),
			updated_at = clock_timestamp()
		FROM locked
		WHERE queue_deliveries.consumer_group = locked.consumer_group
		  AND queue_deliveries.topic = locked.topic
		  AND queue_deliveries.seq = locked.seq
		  AND locked.lease_expires_at > clock_timestamp()
	`, group, topic, seq, owner, attempt, leaseDuration.Milliseconds())
	if err != nil {
		return fmt.Errorf("postgres queue: renew lease: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w for group=%q topic=%q seq=%d", errPostgresQueueStaleLease, group, topic, seq)
	}
	return nil
}

func (s *postgresQueueStore) close() error {
	if s != nil && s.owned && s.pool != nil {
		s.pool.Close()
	}
	return nil
}

func normalizePostgresInitialPosition(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return PostgresInitialPositionEarliest, nil
	}
	switch value {
	case PostgresInitialPositionEarliest, PostgresInitialPositionLatest:
		return value, nil
	default:
		return "", fmt.Errorf("postgres queue: unsupported initial position %q", value)
	}
}

type postgresProducer struct {
	backend postgresQueueBackend
}

func newPostgresProducer(cfg ProducerConfig) (Producer, error) {
	backend, err := newPostgresQueueStore(context.Background(), cfg.PostgresDSN, cfg.PostgresPool)
	if err != nil {
		return nil, err
	}
	return newPostgresProducerWithBackend(backend)
}

func newPostgresProducerWithBackend(backend postgresQueueBackend) (Producer, error) {
	if backend == nil {
		return nil, errors.New("postgres producer requires backend")
	}
	if err := backend.ensureSchema(context.Background()); err != nil {
		return nil, err
	}
	return &postgresProducer{backend: backend}, nil
}

func (p *postgresProducer) Publish(ctx context.Context, topic string, payload []byte) error {
	topic = strings.TrimSpace(topic)
	if topic == "" {
		return errors.New("topic is required")
	}
	return p.backend.enqueue(ctx, topic, append([]byte(nil), payload...))
}

func (p *postgresProducer) Close() error {
	if p == nil || p.backend == nil {
		return nil
	}
	return p.backend.close()
}

type postgresConsumer struct {
	backend          postgresQueueBackend
	group            string
	topics           []string
	owner            string
	initialPosition  string
	initialSequences map[string]int64
	leaseDuration    time.Duration
	maxLeaseDuration time.Duration
	renewInterval    time.Duration
	materializeLimit int
	pollInterval     time.Duration

	msgCh chan Message
	errCh chan error

	mu       sync.Mutex
	inflight map[string]postgresQueueRecord

	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func newPostgresConsumer(parent context.Context, cfg ConsumerConfig) (Consumer, error) {
	backend, err := newPostgresQueueStore(parent, cfg.PostgresDSN, cfg.PostgresPool)
	if err != nil {
		return nil, err
	}
	return newPostgresConsumerWithBackend(parent, cfg, backend)
}

func newPostgresConsumerWithBackend(parent context.Context, cfg ConsumerConfig, backend postgresQueueBackend) (Consumer, error) {
	if backend == nil {
		return nil, errors.New("postgres consumer requires backend")
	}
	group := strings.TrimSpace(cfg.Group)
	if group == "" {
		return nil, errors.New("postgres consumer requires group")
	}
	topics := normalizeDedupedList(cfg.Topics)
	if len(topics) == 0 {
		return nil, errors.New("postgres consumer requires at least one topic")
	}
	leaseDuration := cfg.PostgresLeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = defaultPostgresLeaseDuration
	}
	maxLeaseDuration := cfg.PostgresMaxLeaseDuration
	if maxLeaseDuration <= 0 {
		maxLeaseDuration = 5 * leaseDuration
	}
	if maxLeaseDuration < leaseDuration {
		return nil, errors.New("postgres queue max lease duration must be >= lease duration")
	}
	renewInterval := leaseDuration / 3
	if renewInterval <= 0 {
		renewInterval = leaseDuration
	}
	pollInterval := cfg.PostgresPollInterval
	if pollInterval <= 0 {
		pollInterval = defaultPostgresPollInterval
	}
	materializeLimit := cfg.PostgresMaterializeLimit
	if materializeLimit <= 0 {
		materializeLimit = defaultPostgresMaterializeLimit
	}
	initialPosition, err := normalizePostgresInitialPosition(cfg.PostgresInitialPosition)
	if err != nil {
		return nil, err
	}
	initialSequences := make(map[string]int64, len(cfg.PostgresInitialSequences))
	for rawTopic, seq := range cfg.PostgresInitialSequences {
		topic := strings.TrimSpace(rawTopic)
		if topic == "" {
			return nil, errors.New("postgres queue initial sequence topic is required")
		}
		if seq <= 0 {
			return nil, fmt.Errorf("postgres queue initial sequence for topic %q must be > 0", topic)
		}
		initialSequences[topic] = seq
	}
	owner := strings.TrimSpace(cfg.PostgresOwner)
	if owner == "" {
		owner = defaultPostgresQueueOwner()
	}
	if err := backend.ensureSchema(parent); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(parent)
	c := &postgresConsumer{
		backend:          backend,
		group:            group,
		topics:           topics,
		owner:            owner,
		initialPosition:  initialPosition,
		initialSequences: initialSequences,
		leaseDuration:    leaseDuration,
		maxLeaseDuration: maxLeaseDuration,
		renewInterval:    renewInterval,
		materializeLimit: materializeLimit,
		pollInterval:     pollInterval,
		msgCh:            make(chan Message, 64),
		errCh:            make(chan error, 8),
		inflight:         make(map[string]postgresQueueRecord),
		cancel:           cancel,
		done:             make(chan struct{}),
	}
	go c.run(ctx)
	return c, nil
}

func (c *postgresConsumer) run(ctx context.Context) {
	defer close(c.done)
	defer close(c.msgCh)
	defer close(c.errCh)

	for {
		if err := c.renewInflight(ctx); err != nil {
			select {
			case c.errCh <- err:
			case <-ctx.Done():
				return
			}
		}
		topics := c.claimableTopics()
		if len(topics) == 0 {
			if !sleepOrDone(ctx, c.nextSleepDuration()) {
				return
			}
			continue
		}

		records, err := c.backend.claim(ctx, postgresQueueClaimConfig{
			group:            c.group,
			topics:           topics,
			owner:            c.owner,
			initialPosition:  c.initialPosition,
			initialSequences: c.initialSequences,
			leaseDuration:    c.leaseDuration,
			materializeLimit: c.materializeLimit,
			limit:            1,
		})
		if err != nil {
			select {
			case c.errCh <- err:
			case <-ctx.Done():
				return
			}
			if !sleepOrDone(ctx, c.nextSleepDuration()) {
				return
			}
			continue
		}
		if len(records) == 0 {
			if !sleepOrDone(ctx, c.nextSleepDuration()) {
				return
			}
			continue
		}

		for _, rec := range records {
			rec := rec
			c.trackInflight(rec)
			msg := Message{
				Topic:     rec.topic,
				Value:     append([]byte(nil), rec.payload...),
				Timestamp: rec.createdAt.UTC(),
				ackFn: func(ackCtx context.Context) error {
					err := c.backend.ack(ackCtx, c.group, rec.topic, rec.seq, rec.owner, rec.attempt)
					if err == nil {
						c.untrackInflight(rec)
					}
					return err
				},
			}
			select {
			case c.msgCh <- msg:
			case <-ctx.Done():
				c.untrackInflight(rec)
				return
			}
		}
	}
}

func (c *postgresConsumer) claimableTopics() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	topics := make([]string, 0, len(c.topics))
	for _, topic := range c.topics {
		if _, ok := c.inflight[topic]; ok {
			continue
		}
		topics = append(topics, topic)
	}
	return topics
}

func (c *postgresConsumer) trackInflight(rec postgresQueueRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inflight[rec.topic] = rec
}

func (c *postgresConsumer) untrackInflight(rec postgresQueueRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	current, ok := c.inflight[rec.topic]
	if ok && current.seq == rec.seq && current.attempt == rec.attempt && current.owner == rec.owner {
		delete(c.inflight, rec.topic)
	}
}

func (c *postgresConsumer) renewInflight(ctx context.Context) error {
	c.mu.Lock()
	records := make([]postgresQueueRecord, 0, len(c.inflight))
	for _, rec := range c.inflight {
		records = append(records, rec)
	}
	c.mu.Unlock()

	var errs []error
	now := time.Now()
	for _, rec := range records {
		renewFor := c.leaseDuration
		if !rec.claimedAt.IsZero() && c.maxLeaseDuration > 0 {
			remaining := rec.claimedAt.Add(c.maxLeaseDuration).Sub(now)
			if remaining <= 0 {
				c.untrackInflight(rec)
				continue
			}
			if remaining < renewFor {
				renewFor = remaining
			}
		}
		if err := c.backend.renew(ctx, c.group, rec.topic, rec.seq, rec.owner, rec.attempt, renewFor); err != nil {
			if errors.Is(err, errPostgresQueueStaleLease) {
				c.untrackInflight(rec)
				continue
			}
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *postgresConsumer) nextSleepDuration() time.Duration {
	wait := c.pollInterval
	if wait <= 0 {
		wait = defaultPostgresPollInterval
	}
	if c.hasInflight() && c.renewInterval > 0 && c.renewInterval < wait {
		wait = c.renewInterval
	}
	return wait
}

func (c *postgresConsumer) hasInflight() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.inflight) > 0
}

func (c *postgresConsumer) Messages() <-chan Message {
	return c.msgCh
}

func (c *postgresConsumer) Errors() <-chan error {
	return c.errCh
}

func (c *postgresConsumer) Close() error {
	var err error
	c.once.Do(func() {
		c.cancel()
		<-c.done
		err = c.backend.close()
	})
	return err
}

func defaultPostgresQueueOwner() string {
	host, _ := os.Hostname()
	host = strings.TrimSpace(host)
	if host == "" {
		host = "unknown-host"
	}
	return fmt.Sprintf("%s-%d", host, os.Getpid())
}

func sleepOrDone(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
