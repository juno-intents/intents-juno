package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/pgxpoolutil"
	"github.com/juno-intents/intents-juno/internal/queue"
	"github.com/segmentio/kafka-go"
)

const (
	outputText = "text"
	outputJSON = "json"
)

type config struct {
	QueueDriver      string
	PostgresDSN      string
	PostgresDSNEnv   string
	KafkaBrokers     []string
	Topics           []string
	Groups           []string
	Format           string
	Timeout          time.Duration
	MaxBacklog       int64
	MaxExpiredLeases int64
}

type queueStatsRow struct {
	Topic              string `json:"topic"`
	ConsumerGroup      string `json:"consumerGroup,omitempty"`
	FirstSeq           int64  `json:"firstSeq"`
	LastSeq            int64  `json:"lastSeq"`
	MessageCount       int64  `json:"messageCount"`
	NextSeq            int64  `json:"nextSeq,omitempty"`
	Backlog            int64  `json:"backlog"`
	UnackedDeliveries  int64  `json:"unackedDeliveries"`
	AckedDeliveries    int64  `json:"ackedDeliveries"`
	LeasedDeliveries   int64  `json:"leasedDeliveries"`
	ExpiredLeases      int64  `json:"expiredLeases"`
	MaxAttemptCount    int64  `json:"maxAttemptCount"`
	LastMessageAgeSecs int64  `json:"lastMessageAgeSeconds,omitempty"`
}

type inspectReport struct {
	GeneratedAtUTC     string          `json:"generatedAtUtc"`
	Rows               []queueStatsRow `json:"rows"`
	TotalBacklog       int64           `json:"totalBacklog"`
	TotalExpiredLeases int64           `json:"totalExpiredLeases"`
}

type queueInspector interface {
	Inspect(ctx context.Context, topics, groups []string) ([]queueStatsRow, error)
}

type postgresInspector struct {
	pool *pgxpool.Pool
}

type kafkaInspector struct {
	brokers []string
	timeout time.Duration
}

type kafkaPartitionLag struct {
	Topic           string
	Partition       int
	FirstOffset     int64
	LastOffset      int64
	CommittedOffset int64
}

type kafkaGroupLag struct {
	Topic      string
	Group      string
	Partitions []kafkaPartitionLag
}

func main() {
	if err := runMain(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runMain(parent context.Context, args []string, stdout io.Writer) error {
	cfg, err := parseArgs(args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, cfg.Timeout)
	defer cancel()

	switch cfg.QueueDriver {
	case queue.DriverPostgres:
		dsn, err := pgxpoolutil.ResolveDSN(cfg.PostgresDSN, cfg.PostgresDSNEnv)
		if err != nil {
			return err
		}
		poolCfg, err := pgxpoolutil.ParseConfig(dsn, pgxpoolutil.Settings{})
		if err != nil {
			return err
		}
		pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
		if err != nil {
			return fmt.Errorf("connect postgres: %w", err)
		}
		defer pool.Close()
		return runMainWithInspector(ctx, args, stdout, postgresInspector{pool: pool})
	case queue.DriverKafka:
		return runMainWithInspector(ctx, args, stdout, kafkaInspector{brokers: cfg.KafkaBrokers, timeout: cfg.Timeout})
	default:
		return fmt.Errorf("unsupported queue driver %q", cfg.QueueDriver)
	}
}

func runMainWithInspector(ctx context.Context, args []string, stdout io.Writer, inspector queueInspector) error {
	cfg, err := parseArgs(args)
	if err != nil {
		return err
	}
	rows, err := inspector.Inspect(ctx, cfg.Topics, cfg.Groups)
	if err != nil {
		return err
	}
	rep := buildReport(rows)
	thresholdErr := checkThresholds(cfg, rows)
	if err := writeReport(stdout, cfg.Format, rep); err != nil {
		return err
	}
	return thresholdErr
}

func parseArgs(args []string) (config, error) {
	fs := flag.NewFlagSet("queue-inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var topicsRaw string
	var groupsRaw string
	var brokersRaw string
	cfg := config{
		QueueDriver:      queue.DriverPostgres,
		Format:           outputText,
		Timeout:          30 * time.Second,
		MaxBacklog:       -1,
		MaxExpiredLeases: -1,
	}
	fs.StringVar(&cfg.QueueDriver, "queue-driver", cfg.QueueDriver, "queue driver to inspect: postgres|kafka")
	fs.StringVar(&cfg.PostgresDSN, "postgres-dsn", "", "Postgres DSN for queue inspection")
	fs.StringVar(&cfg.PostgresDSNEnv, "postgres-dsn-env", "", "env var containing Postgres DSN for queue inspection")
	fs.StringVar(&brokersRaw, "kafka-brokers", "", "comma-separated Kafka brokers for kafka queue inspection")
	fs.StringVar(&topicsRaw, "topics", "", "comma-separated queue topics to inspect (default: all)")
	fs.StringVar(&groupsRaw, "groups", "", "comma-separated consumer groups to inspect (default: all)")
	fs.StringVar(&cfg.Format, "format", outputText, "output format: text|json")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "overall inspection timeout")
	fs.Int64Var(&cfg.MaxBacklog, "max-backlog", cfg.MaxBacklog, "fail if any topic/group backlog exceeds this value (-1 disables)")
	fs.Int64Var(&cfg.MaxExpiredLeases, "max-expired-leases", cfg.MaxExpiredLeases, "fail if any topic/group expired leases exceeds this value (-1 disables)")

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	cfg.QueueDriver = strings.ToLower(strings.TrimSpace(cfg.QueueDriver))
	cfg.Topics = normalizeFilterList(queue.SplitCommaList(topicsRaw))
	cfg.Groups = normalizeFilterList(queue.SplitCommaList(groupsRaw))
	cfg.KafkaBrokers = normalizeFilterList(queue.SplitCommaList(brokersRaw))
	cfg.Format = strings.ToLower(strings.TrimSpace(cfg.Format))
	switch cfg.Format {
	case outputText, outputJSON:
	default:
		return config{}, fmt.Errorf("--format must be %s or %s", outputText, outputJSON)
	}
	if cfg.Timeout <= 0 {
		return config{}, errors.New("--timeout must be > 0")
	}
	if cfg.MaxBacklog < -1 {
		return config{}, errors.New("--max-backlog must be >= -1")
	}
	if cfg.MaxExpiredLeases < -1 {
		return config{}, errors.New("--max-expired-leases must be >= -1")
	}
	switch cfg.QueueDriver {
	case queue.DriverPostgres:
		if strings.TrimSpace(cfg.PostgresDSN) == "" && strings.TrimSpace(cfg.PostgresDSNEnv) == "" {
			return config{}, errors.New("--postgres-dsn or --postgres-dsn-env is required")
		}
	case queue.DriverKafka:
		if len(cfg.KafkaBrokers) == 0 {
			return config{}, errors.New("--kafka-brokers is required when --queue-driver=kafka")
		}
		if len(cfg.Topics) == 0 {
			return config{}, errors.New("--topics is required when --queue-driver=kafka")
		}
		if len(cfg.Groups) == 0 {
			return config{}, errors.New("--groups is required when --queue-driver=kafka")
		}
	default:
		return config{}, fmt.Errorf("--queue-driver must be %s or %s", queue.DriverPostgres, queue.DriverKafka)
	}
	return cfg, nil
}

func (i postgresInspector) Inspect(ctx context.Context, topics, groups []string) ([]queueStatsRow, error) {
	if i.pool == nil {
		return nil, errors.New("nil postgres pool")
	}
	topics = normalizeFilterList(topics)
	groups = normalizeFilterList(groups)
	rows, err := i.pool.Query(ctx, `
WITH requested_topics AS (
	SELECT unnest($1::text[]) AS topic
),
requested_groups AS (
	SELECT unnest($2::text[]) AS consumer_group
),
topic_stats AS (
	SELECT
		topic,
		COALESCE(min(seq), 0)::bigint AS first_seq,
		COALESCE(max(seq), 0)::bigint AS last_seq,
		count(*)::bigint AS message_count,
		COALESCE(floor(extract(epoch FROM (now() - max(created_at))))::bigint, 0) AS last_message_age_seconds
	FROM queue_messages
	WHERE (cardinality($1::text[]) = 0 OR topic = ANY($1::text[]))
	GROUP BY topic
),
actual_groups AS (
	SELECT topic, consumer_group
	FROM queue_group_offsets
	WHERE (cardinality($1::text[]) = 0 OR topic = ANY($1::text[]))
		AND (cardinality($2::text[]) = 0 OR consumer_group = ANY($2::text[]))
	UNION
	SELECT topic, consumer_group
	FROM queue_deliveries
	WHERE (cardinality($1::text[]) = 0 OR topic = ANY($1::text[]))
		AND (cardinality($2::text[]) = 0 OR consumer_group = ANY($2::text[]))
),
known_topics AS (
	SELECT topic FROM requested_topics
	UNION
	SELECT topic FROM topic_stats
	UNION
	SELECT topic FROM actual_groups
),
groups AS (
	SELECT kt.topic, rg.consumer_group
	FROM known_topics kt
	CROSS JOIN requested_groups rg
	WHERE cardinality($2::text[]) > 0
	UNION
	SELECT topic, consumer_group
	FROM actual_groups
	WHERE cardinality($2::text[]) = 0
),
delivery_stats AS (
	SELECT
		topic,
		consumer_group,
		count(*) FILTER (WHERE acked_at IS NULL)::bigint AS unacked_deliveries,
		count(*) FILTER (WHERE acked_at IS NOT NULL)::bigint AS acked_deliveries,
		count(*) FILTER (WHERE acked_at IS NULL AND lease_owner IS NOT NULL AND lease_expires_at > now())::bigint AS leased_deliveries,
		count(*) FILTER (WHERE acked_at IS NULL AND lease_owner IS NOT NULL AND lease_expires_at <= now())::bigint AS expired_leases,
		COALESCE(max(attempt_count), 0)::bigint AS max_attempt_count
	FROM queue_deliveries
	WHERE (cardinality($1::text[]) = 0 OR topic = ANY($1::text[]))
		AND (cardinality($2::text[]) = 0 OR consumer_group = ANY($2::text[]))
	GROUP BY topic, consumer_group
)
SELECT
	COALESCE(ts.topic, g.topic) AS topic,
	COALESCE(g.consumer_group, '') AS consumer_group,
	COALESCE(ts.first_seq, 0)::bigint AS first_seq,
	COALESCE(ts.last_seq, 0)::bigint AS last_seq,
	COALESCE(ts.message_count, 0)::bigint AS message_count,
	COALESCE(o.next_seq, 0)::bigint AS next_seq,
	CASE
		WHEN g.consumer_group IS NULL OR ts.last_seq IS NULL THEN 0
		ELSE GREATEST(ts.last_seq - COALESCE(o.next_seq, 1) + 1, 0)
	END::bigint AS backlog,
	COALESCE(ds.unacked_deliveries, 0)::bigint AS unacked_deliveries,
	COALESCE(ds.acked_deliveries, 0)::bigint AS acked_deliveries,
	COALESCE(ds.leased_deliveries, 0)::bigint AS leased_deliveries,
	COALESCE(ds.expired_leases, 0)::bigint AS expired_leases,
	COALESCE(ds.max_attempt_count, 0)::bigint AS max_attempt_count,
	COALESCE(ts.last_message_age_seconds, 0)::bigint AS last_message_age_seconds
FROM topic_stats ts
FULL OUTER JOIN groups g ON g.topic = ts.topic
LEFT JOIN queue_group_offsets o ON o.topic = g.topic AND o.consumer_group = g.consumer_group
LEFT JOIN delivery_stats ds ON ds.topic = g.topic AND ds.consumer_group = g.consumer_group
ORDER BY topic, consumer_group
`, topics, groups)
	if err != nil {
		return nil, fmt.Errorf("inspect postgres queue: %w", err)
	}
	defer rows.Close()

	var out []queueStatsRow
	for rows.Next() {
		var row queueStatsRow
		if err := rows.Scan(
			&row.Topic,
			&row.ConsumerGroup,
			&row.FirstSeq,
			&row.LastSeq,
			&row.MessageCount,
			&row.NextSeq,
			&row.Backlog,
			&row.UnackedDeliveries,
			&row.AckedDeliveries,
			&row.LeasedDeliveries,
			&row.ExpiredLeases,
			&row.MaxAttemptCount,
			&row.LastMessageAgeSecs,
		); err != nil {
			return nil, fmt.Errorf("scan postgres queue stats: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read postgres queue stats: %w", err)
	}
	return out, nil
}

func (i kafkaInspector) Inspect(ctx context.Context, topics, groups []string) ([]queueStatsRow, error) {
	topics = normalizeFilterList(topics)
	groups = normalizeFilterList(groups)
	if len(i.brokers) == 0 {
		return nil, errors.New("kafka brokers are required")
	}
	if len(topics) == 0 {
		return nil, errors.New("kafka topics are required")
	}
	if len(groups) == 0 {
		return nil, errors.New("kafka consumer groups are required")
	}
	timeout := i.timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	transport, err := queue.NewKafkaTransportFromEnv()
	if err != nil {
		return nil, fmt.Errorf("init kafka transport: %w", err)
	}
	client := &kafka.Client{
		Addr:      kafka.TCP(i.brokers...),
		Timeout:   timeout,
		Transport: transport,
	}

	partitionsByTopic, err := kafkaTopicPartitions(ctx, client, topics)
	if err != nil {
		return nil, err
	}
	offsetsByPartition, err := kafkaPartitionOffsets(ctx, client, i.brokers[0], partitionsByTopic)
	if err != nil {
		return nil, err
	}

	lags := make([]kafkaGroupLag, 0, len(topics)*len(groups))
	for _, group := range groups {
		topicPartitions := make(map[string][]int, len(partitionsByTopic))
		for topic, partitions := range partitionsByTopic {
			for _, partition := range partitions {
				topicPartitions[topic] = append(topicPartitions[topic], partition.ID)
			}
			sort.Ints(topicPartitions[topic])
		}
		committed, err := kafkaCommittedOffsets(ctx, client, group, topicPartitions)
		if err != nil {
			return nil, err
		}
		for _, topic := range topics {
			groupLag := kafkaGroupLag{Topic: topic, Group: group}
			for _, partition := range partitionsByTopic[topic] {
				key := kafkaPartitionKey{topic: topic, partition: partition.ID}
				offsets, ok := offsetsByPartition[key]
				if !ok {
					return nil, fmt.Errorf("missing kafka offsets topic=%s partition=%d", topic, partition.ID)
				}
				groupLag.Partitions = append(groupLag.Partitions, kafkaPartitionLag{
					Topic:           topic,
					Partition:       partition.ID,
					FirstOffset:     offsets.FirstOffset,
					LastOffset:      offsets.LastOffset,
					CommittedOffset: committedOffset(committed, topic, partition.ID),
				})
			}
			lags = append(lags, groupLag)
		}
	}
	return buildKafkaLagRows(lags), nil
}

type kafkaPartitionKey struct {
	topic     string
	partition int
}

func kafkaTopicPartitions(ctx context.Context, client *kafka.Client, topics []string) (map[string][]kafka.Partition, error) {
	meta, err := client.Metadata(ctx, &kafka.MetadataRequest{Topics: topics})
	if err != nil {
		return nil, fmt.Errorf("inspect kafka metadata: %w", err)
	}
	byTopic := make(map[string]kafka.Topic, len(meta.Topics))
	for _, topicMeta := range meta.Topics {
		byTopic[topicMeta.Name] = topicMeta
	}
	out := make(map[string][]kafka.Partition, len(topics))
	for _, topic := range topics {
		topicMeta, ok := byTopic[topic]
		if !ok {
			return nil, fmt.Errorf("kafka topic missing: %s", topic)
		}
		if topicMeta.Error != nil {
			return nil, fmt.Errorf("inspect kafka topic metadata topic=%s: %w", topic, topicMeta.Error)
		}
		if len(topicMeta.Partitions) == 0 {
			return nil, fmt.Errorf("kafka topic has no partitions: %s", topic)
		}
		partitions := append([]kafka.Partition(nil), topicMeta.Partitions...)
		sort.Slice(partitions, func(a, b int) bool { return partitions[a].ID < partitions[b].ID })
		for _, partition := range partitions {
			if partition.Error != nil {
				return nil, fmt.Errorf("inspect kafka partition metadata topic=%s partition=%d: %w", topic, partition.ID, partition.Error)
			}
		}
		out[topic] = partitions
	}
	return out, nil
}

func kafkaPartitionOffsets(ctx context.Context, client *kafka.Client, fallbackBroker string, partitionsByTopic map[string][]kafka.Partition) (map[kafkaPartitionKey]kafka.PartitionOffsets, error) {
	type leaderRequest struct {
		addr   net.Addr
		topics map[string][]kafka.OffsetRequest
	}
	byLeader := map[string]leaderRequest{}
	for topic, partitions := range partitionsByTopic {
		for _, partition := range partitions {
			leader := kafkaLeaderAddr(partition, fallbackBroker)
			req := byLeader[leader.String()]
			if req.topics == nil {
				req = leaderRequest{addr: leader, topics: map[string][]kafka.OffsetRequest{}}
			}
			req.topics[topic] = append(req.topics[topic], kafka.FirstOffsetOf(partition.ID), kafka.LastOffsetOf(partition.ID))
			byLeader[leader.String()] = req
		}
	}
	out := map[kafkaPartitionKey]kafka.PartitionOffsets{}
	for _, req := range byLeader {
		resp, err := client.ListOffsets(ctx, &kafka.ListOffsetsRequest{
			Addr:   req.addr,
			Topics: req.topics,
		})
		if err != nil {
			return nil, fmt.Errorf("list kafka offsets via %s: %w", req.addr, err)
		}
		for topic, partitions := range resp.Topics {
			for _, partition := range partitions {
				if partition.Error != nil {
					return nil, fmt.Errorf("list kafka offsets topic=%s partition=%d: %w", topic, partition.Partition, partition.Error)
				}
				out[kafkaPartitionKey{topic: topic, partition: partition.Partition}] = partition
			}
		}
	}
	return out, nil
}

func kafkaCommittedOffsets(ctx context.Context, client *kafka.Client, group string, topics map[string][]int) (map[string]map[int]int64, error) {
	coordinatorAddr, err := kafkaConsumerGroupCoordinator(ctx, client, group)
	if err != nil {
		return nil, err
	}
	resp, err := client.OffsetFetch(ctx, &kafka.OffsetFetchRequest{
		Addr:    coordinatorAddr,
		GroupID: group,
		Topics:  topics,
	})
	if err != nil {
		return nil, fmt.Errorf("fetch kafka group offsets group=%s: %w", group, err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("fetch kafka group offsets group=%s: %w", group, resp.Error)
	}
	out := make(map[string]map[int]int64, len(resp.Topics))
	for topic, partitions := range resp.Topics {
		if out[topic] == nil {
			out[topic] = map[int]int64{}
		}
		for _, partition := range partitions {
			if partition.Error != nil {
				return nil, fmt.Errorf("fetch kafka group offset group=%s topic=%s partition=%d: %w", group, topic, partition.Partition, partition.Error)
			}
			out[topic][partition.Partition] = partition.CommittedOffset
		}
	}
	return out, nil
}

func kafkaConsumerGroupCoordinator(ctx context.Context, client *kafka.Client, group string) (net.Addr, error) {
	resp, err := client.FindCoordinator(ctx, &kafka.FindCoordinatorRequest{
		Key:     group,
		KeyType: kafka.CoordinatorKeyTypeConsumer,
	})
	if err != nil {
		return nil, fmt.Errorf("find kafka consumer group coordinator group=%s: %w", group, err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("find kafka consumer group coordinator group=%s: %w", group, resp.Error)
	}
	if resp.Coordinator == nil || resp.Coordinator.Host == "" || resp.Coordinator.Port == 0 {
		return nil, fmt.Errorf("find kafka consumer group coordinator group=%s: coordinator missing host or port", group)
	}
	return kafka.TCP(net.JoinHostPort(resp.Coordinator.Host, strconv.Itoa(resp.Coordinator.Port))), nil
}

func kafkaLeaderAddr(partition kafka.Partition, fallbackBroker string) net.Addr {
	if partition.Leader.Host == "" || partition.Leader.Port == 0 {
		return kafka.TCP(fallbackBroker)
	}
	return kafka.TCP(net.JoinHostPort(partition.Leader.Host, strconv.Itoa(partition.Leader.Port)))
}

func committedOffset(committed map[string]map[int]int64, topic string, partition int) int64 {
	byPartition, ok := committed[topic]
	if !ok {
		return -1
	}
	offset, ok := byPartition[partition]
	if !ok {
		return -1
	}
	return offset
}

func buildKafkaLagRows(lags []kafkaGroupLag) []queueStatsRow {
	rows := make([]queueStatsRow, 0, len(lags))
	for _, lag := range lags {
		row := queueStatsRow{
			Topic:         lag.Topic,
			ConsumerGroup: lag.Group,
		}
		if len(lag.Partitions) == 0 {
			rows = append(rows, row)
			continue
		}
		var firstSet bool
		var nextSet bool
		for _, partition := range lag.Partitions {
			first := partition.FirstOffset
			end := partition.LastOffset
			if end < first {
				end = first
			}
			if !firstSet || first < row.FirstSeq {
				row.FirstSeq = first
				firstSet = true
			}
			lastMessageOffset := end - 1
			if end <= first {
				lastMessageOffset = 0
			}
			if lastMessageOffset > row.LastSeq {
				row.LastSeq = lastMessageOffset
			}
			messageCount := end - first
			if messageCount > 0 {
				row.MessageCount += messageCount
			}
			next := partition.CommittedOffset
			if next < first {
				next = first
			}
			if !nextSet || next < row.NextSeq {
				row.NextSeq = next
				nextSet = true
			}
			backlog := end - next
			if backlog > 0 {
				row.Backlog += backlog
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func buildReport(rows []queueStatsRow) inspectReport {
	rep := inspectReport{
		GeneratedAtUTC: time.Now().UTC().Format(time.RFC3339),
		Rows:           append([]queueStatsRow(nil), rows...),
	}
	for _, row := range rows {
		rep.TotalBacklog += row.Backlog
		rep.TotalExpiredLeases += row.ExpiredLeases
	}
	return rep
}

func normalizeFilterList(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func checkThresholds(cfg config, rows []queueStatsRow) error {
	for _, row := range rows {
		if cfg.MaxBacklog >= 0 && row.Backlog > cfg.MaxBacklog {
			return fmt.Errorf("queue backlog threshold exceeded topic=%s group=%s backlog=%d max=%d", row.Topic, row.ConsumerGroup, row.Backlog, cfg.MaxBacklog)
		}
		if cfg.MaxExpiredLeases >= 0 && row.ExpiredLeases > cfg.MaxExpiredLeases {
			return fmt.Errorf("queue expired leases threshold exceeded topic=%s group=%s expired_leases=%d max=%d", row.Topic, row.ConsumerGroup, row.ExpiredLeases, cfg.MaxExpiredLeases)
		}
	}
	return nil
}

func writeReport(stdout io.Writer, format string, rep inspectReport) error {
	switch format {
	case outputJSON:
		out, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "%s\n", out)
		return err
	case outputText:
		if len(rep.Rows) == 0 {
			_, err := fmt.Fprintln(stdout, "no postgres queue rows found")
			return err
		}
		for _, row := range rep.Rows {
			group := row.ConsumerGroup
			if group == "" {
				group = "-"
			}
			if _, err := fmt.Fprintf(
				stdout,
				"topic=%s group=%s messages=%d first_seq=%d last_seq=%d next_seq=%d backlog=%d unacked=%d leased=%d expired_leases=%d max_attempt=%d last_message_age_seconds=%d\n",
				row.Topic,
				group,
				row.MessageCount,
				row.FirstSeq,
				row.LastSeq,
				row.NextSeq,
				row.Backlog,
				row.UnackedDeliveries,
				row.LeasedDeliveries,
				row.ExpiredLeases,
				row.MaxAttemptCount,
				row.LastMessageAgeSecs,
			); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(stdout, "total_backlog=%d total_expired_leases=%d\n", rep.TotalBacklog, rep.TotalExpiredLeases)
		return err
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}
