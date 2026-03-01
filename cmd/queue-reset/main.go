package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

func main() {
	if err := runMain(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

type resetMode int

const (
	resetModeNone resetMode = iota
	resetModeBeginning
	resetModeLatest
	resetModeOffset
)

type config struct {
	brokers     []string
	group       string
	topic       string
	mode        resetMode
	targetOffset int64
	dryRun      bool
}

func parseFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("queue-reset", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	brokersStr := fs.String("brokers", "", "comma-separated Kafka broker addresses (required)")
	group := fs.String("group", "", "consumer group ID (required)")
	topic := fs.String("topic", "", "Kafka topic (required)")
	toBeginning := fs.Bool("to-beginning", false, "reset offsets to earliest")
	toLatest := fs.Bool("to-latest", false, "reset offsets to latest")
	toOffset := fs.Int64("to-offset", -1, "reset offsets to specific offset")
	dryRun := fs.Bool("dry-run", true, "only print what would happen (default true)")

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}

	if strings.TrimSpace(*brokersStr) == "" {
		return config{}, errors.New("--brokers is required")
	}
	if strings.TrimSpace(*group) == "" {
		return config{}, errors.New("--group is required")
	}
	if strings.TrimSpace(*topic) == "" {
		return config{}, errors.New("--topic is required")
	}

	brokers := splitCommaList(*brokersStr)
	if len(brokers) == 0 {
		return config{}, errors.New("--brokers requires at least one broker address")
	}

	modeCount := 0
	mode := resetModeNone
	var target int64
	if *toBeginning {
		modeCount++
		mode = resetModeBeginning
	}
	if *toLatest {
		modeCount++
		mode = resetModeLatest
	}
	if *toOffset >= 0 {
		modeCount++
		mode = resetModeOffset
		target = *toOffset
	}
	if modeCount > 1 {
		return config{}, errors.New("specify only one of --to-beginning, --to-latest, or --to-offset")
	}
	if modeCount == 0 && !*dryRun {
		return config{}, errors.New("specify --to-beginning, --to-latest, or --to-offset when --dry-run=false")
	}

	return config{
		brokers:      brokers,
		group:        strings.TrimSpace(*group),
		topic:        strings.TrimSpace(*topic),
		mode:         mode,
		targetOffset: target,
		dryRun:       *dryRun,
	}, nil
}

func runMain(args []string, stdout, stderr io.Writer) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return executeReset(ctx, cfg, stdout, stderr)
}

func executeReset(ctx context.Context, cfg config, stdout, stderr io.Writer) error {
	// Fetch current offsets for the group.
	currentOffsets, err := fetchGroupOffsets(ctx, cfg.brokers, cfg.group, cfg.topic)
	if err != nil {
		return fmt.Errorf("fetch current offsets: %w", err)
	}

	fmt.Fprintf(stdout, "Consumer group: %s\n", cfg.group)
	fmt.Fprintf(stdout, "Topic:          %s\n\n", cfg.topic)
	fmt.Fprintf(stdout, "Current offsets:\n")
	if len(currentOffsets) == 0 {
		fmt.Fprintf(stdout, "  (no partitions found)\n")
	}
	for partition, offset := range currentOffsets {
		fmt.Fprintf(stdout, "  partition %d: offset %d\n", partition, offset)
	}

	if cfg.dryRun {
		if cfg.mode != resetModeNone {
			fmt.Fprintf(stdout, "\nDry run — no changes made.\n")
			fmt.Fprintf(stdout, "Would reset to: %s\n", modeName(cfg.mode, cfg.targetOffset))
		}
		return nil
	}

	// Determine target offsets.
	targetOffsets, err := resolveTargetOffsets(ctx, cfg, currentOffsets)
	if err != nil {
		return fmt.Errorf("resolve target offsets: %w", err)
	}

	// Perform the reset.
	if err := commitOffsets(ctx, cfg.brokers, cfg.group, cfg.topic, targetOffsets); err != nil {
		return fmt.Errorf("commit offsets: %w", err)
	}

	fmt.Fprintf(stdout, "\nNew offsets:\n")
	for partition, offset := range targetOffsets {
		fmt.Fprintf(stdout, "  partition %d: offset %d\n", partition, offset)
	}
	fmt.Fprintf(stdout, "\nOffset reset complete.\n")
	return nil
}

func fetchGroupOffsets(ctx context.Context, brokers []string, group, topic string) (map[int]int64, error) {
	conn, err := kafka.DialContext(ctx, "tcp", brokers[0])
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	partitions, err := conn.ReadPartitions(topic)
	if err != nil {
		return nil, fmt.Errorf("read partitions for %q: %w", topic, err)
	}

	offsets := make(map[int]int64, len(partitions))

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: brokers,
		GroupID: group,
		Topic:   topic,
	})
	defer reader.Close()

	for _, p := range partitions {
		partReader := kafka.NewReader(kafka.ReaderConfig{
			Brokers:   brokers,
			GroupID:   group,
			Topic:     topic,
			Partition: p.ID,
		})
		_ = partReader.Close()
		offsets[p.ID] = -1 // placeholder; actual offset requires OffsetFetch
	}

	// Use a dedicated connection per partition for OffsetFetch.
	for _, p := range partitions {
		pConn, err := kafka.DialLeader(ctx, "tcp", brokers[0], topic, p.ID)
		if err != nil {
			return nil, fmt.Errorf("dial partition %d: %w", p.ID, err)
		}

		offsetFetchReq := kafka.OffsetFetchRequest{
			Addr:    pConn.RemoteAddr(),
			GroupID: group,
			Topics: map[string][]int{
				topic: {p.ID},
			},
		}

		client := &kafka.Client{Addr: kafka.TCP(brokers...)}
		resp, err := client.OffsetFetch(ctx, &offsetFetchReq)
		_ = pConn.Close()
		if err != nil {
			return nil, fmt.Errorf("offset fetch partition %d: %w", p.ID, err)
		}

		if topicOffsets, ok := resp.Topics[topic]; ok {
			for _, po := range topicOffsets {
				if po.Error != nil {
					continue
				}
				offsets[po.Partition] = po.CommittedOffset
			}
		}
	}

	return offsets, nil
}

func resolveTargetOffsets(ctx context.Context, cfg config, currentOffsets map[int]int64) (map[int]int64, error) {
	targets := make(map[int]int64, len(currentOffsets))

	switch cfg.mode {
	case resetModeOffset:
		for p := range currentOffsets {
			targets[p] = cfg.targetOffset
		}
	case resetModeBeginning:
		client := &kafka.Client{Addr: kafka.TCP(cfg.brokers...)}
		resp, err := client.ListOffsets(ctx, &kafka.ListOffsetsRequest{
			Topics: map[string][]kafka.OffsetRequest{
				cfg.topic: partitionOffsetRequests(currentOffsets, kafka.FirstOffset),
			},
		})
		if err != nil {
			return nil, fmt.Errorf("list earliest offsets: %w", err)
		}
		for _, po := range resp.Topics[cfg.topic] {
			if po.Error != nil {
				return nil, fmt.Errorf("earliest offset for partition %d: %w", po.Partition, po.Error)
			}
			targets[po.Partition] = po.FirstOffset
		}
	case resetModeLatest:
		client := &kafka.Client{Addr: kafka.TCP(cfg.brokers...)}
		resp, err := client.ListOffsets(ctx, &kafka.ListOffsetsRequest{
			Topics: map[string][]kafka.OffsetRequest{
				cfg.topic: partitionOffsetRequests(currentOffsets, kafka.LastOffset),
			},
		})
		if err != nil {
			return nil, fmt.Errorf("list latest offsets: %w", err)
		}
		for _, po := range resp.Topics[cfg.topic] {
			if po.Error != nil {
				return nil, fmt.Errorf("latest offset for partition %d: %w", po.Partition, po.Error)
			}
			targets[po.Partition] = po.LastOffset
		}
	default:
		return nil, errors.New("no reset mode specified")
	}

	return targets, nil
}

func partitionOffsetRequests(offsets map[int]int64, timestamp int64) []kafka.OffsetRequest {
	reqs := make([]kafka.OffsetRequest, 0, len(offsets))
	for p := range offsets {
		reqs = append(reqs, kafka.OffsetRequest{Partition: p, Timestamp: timestamp})
	}
	return reqs
}

func commitOffsets(ctx context.Context, brokers []string, group, topic string, offsets map[int]int64) error {
	client := &kafka.Client{Addr: kafka.TCP(brokers...)}

	partitionOffsets := make(map[string][]kafka.OffsetCommit, 1)
	commits := make([]kafka.OffsetCommit, 0, len(offsets))
	for p, off := range offsets {
		commits = append(commits, kafka.OffsetCommit{Partition: p, Offset: off})
	}
	partitionOffsets[topic] = commits

	_, err := client.OffsetCommit(ctx, &kafka.OffsetCommitRequest{
		Addr:    client.Addr,
		GroupID: group,
		Topics:  partitionOffsets,
	})
	return err
}

func modeName(mode resetMode, offset int64) string {
	switch mode {
	case resetModeBeginning:
		return "beginning (earliest)"
	case resetModeLatest:
		return "latest"
	case resetModeOffset:
		return fmt.Sprintf("offset %d", offset)
	default:
		return "none"
	}
}

func splitCommaList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
