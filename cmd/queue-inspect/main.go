package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/pgxpoolutil"
	"github.com/juno-intents/intents-juno/internal/queue"
)

const (
	outputText = "text"
	outputJSON = "json"
)

type config struct {
	PostgresDSN      string
	PostgresDSNEnv   string
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
	cfg := config{
		Format:           outputText,
		Timeout:          30 * time.Second,
		MaxBacklog:       -1,
		MaxExpiredLeases: -1,
	}
	fs.StringVar(&cfg.PostgresDSN, "postgres-dsn", "", "Postgres DSN for queue inspection")
	fs.StringVar(&cfg.PostgresDSNEnv, "postgres-dsn-env", "", "env var containing Postgres DSN for queue inspection")
	fs.StringVar(&topicsRaw, "topics", "", "comma-separated queue topics to inspect (default: all)")
	fs.StringVar(&groupsRaw, "groups", "", "comma-separated consumer groups to inspect (default: all)")
	fs.StringVar(&cfg.Format, "format", outputText, "output format: text|json")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "overall inspection timeout")
	fs.Int64Var(&cfg.MaxBacklog, "max-backlog", cfg.MaxBacklog, "fail if any topic/group backlog exceeds this value (-1 disables)")
	fs.Int64Var(&cfg.MaxExpiredLeases, "max-expired-leases", cfg.MaxExpiredLeases, "fail if any topic/group expired leases exceeds this value (-1 disables)")

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if strings.TrimSpace(cfg.PostgresDSN) == "" && strings.TrimSpace(cfg.PostgresDSNEnv) == "" {
		return config{}, errors.New("--postgres-dsn or --postgres-dsn-env is required")
	}
	cfg.Topics = normalizeFilterList(queue.SplitCommaList(topicsRaw))
	cfg.Groups = normalizeFilterList(queue.SplitCommaList(groupsRaw))
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
