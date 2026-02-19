package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/juno-intents/intents-juno/internal/queue"
)

type stringListFlag []string

func (f *stringListFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return errors.New("value must not be empty")
	}
	*f = append(*f, v)
	return nil
}

func main() {
	if err := runMain(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runMain(args []string, stdin io.Reader, stdout io.Writer) error {
	var payloadFiles stringListFlag
	fs := flag.NewFlagSet("queue-publish", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	queueDriver := fs.String("queue-driver", queue.DriverKafka, "queue driver: kafka|stdio")
	queueBrokers := fs.String("queue-brokers", "", "comma-separated queue brokers (required for kafka)")
	topic := fs.String("topic", "", "queue topic (required)")
	payload := fs.String("payload", "", "inline payload body")
	fs.Var(&payloadFiles, "payload-file", "payload file path (repeatable)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*topic) == "" {
		return errors.New("--topic is required")
	}

	producer, err := queue.NewProducer(queue.ProducerConfig{
		Driver:  *queueDriver,
		Brokers: queue.SplitCommaList(*queueBrokers),
		Writer:  stdout,
	})
	if err != nil {
		return err
	}
	defer func() { _ = producer.Close() }()

	payloads, err := loadPayloads(strings.TrimSpace(*payload), payloadFiles, stdin)
	if err != nil {
		return err
	}

	ctx := context.Background()
	for _, p := range payloads {
		if len(bytes.TrimSpace(p)) == 0 {
			continue
		}
		if err := producer.Publish(ctx, *topic, p); err != nil {
			return err
		}
	}
	return nil
}

func loadPayloads(payloadInline string, payloadFiles []string, stdin io.Reader) ([][]byte, error) {
	payloads := make([][]byte, 0, len(payloadFiles)+1)
	if payloadInline != "" {
		payloads = append(payloads, []byte(payloadInline))
	}
	for _, filePath := range payloadFiles {
		b, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read payload file %q: %w", filePath, err)
		}
		payloads = append(payloads, b)
	}
	if len(payloads) > 0 {
		return payloads, nil
	}
	if stdin == nil {
		return nil, errors.New("payload is required via --payload, --payload-file, or stdin")
	}
	b, err := io.ReadAll(stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin payload: %w", err)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, errors.New("payload is required via --payload, --payload-file, or stdin")
	}
	return [][]byte{b}, nil
}
