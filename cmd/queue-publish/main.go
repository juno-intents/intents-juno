package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/juno-intents/intents-juno/internal/queue"
	"github.com/juno-intents/intents-juno/internal/queueauth"
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
	if err := runMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

type auditRecord struct {
	Topic         string `json:"topic"`
	Critical      bool   `json:"critical"`
	DryRun        bool   `json:"dryRun"`
	KeyID         string `json:"keyId,omitempty"`
	PayloadSHA256 string `json:"payloadSha256"`
	WireSHA256    string `json:"wireSha256,omitempty"`
	PayloadBytes  int    `json:"payloadBytes"`
	WireBytes     int    `json:"wireBytes,omitempty"`
	Status        string `json:"status"`
	Error         string `json:"error,omitempty"`
}

func runMain(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	var payloadFiles stringListFlag
	fs := flag.NewFlagSet("queue-publish", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	queueDriver := fs.String("queue-driver", queue.DriverKafka, "queue driver: kafka|stdio")
	queueBrokers := fs.String("queue-brokers", "", "comma-separated queue brokers (required for kafka)")
	topic := fs.String("topic", "", "queue topic (required)")
	payload := fs.String("payload", "", "inline payload body")
	fs.Var(&payloadFiles, "payload-file", "payload file path (repeatable)")
	dryRun := fs.Bool("dry-run", false, "validate payloads and emit audit logs without publishing")
	queueAuthKeyID := fs.String("queue-auth-key-id", "", "critical-topic signing key id")
	queueAuthKeyIDEnv := fs.String("queue-auth-key-id-env", queueauth.DefaultKeyIDEnv, "env var containing critical-topic signing key id")
	queueAuthHMACEnv := fs.String("queue-auth-hmac-env", queueauth.DefaultHMACEnv, "env var containing critical-topic HMAC secret")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*topic) == "" {
		return errors.New("--topic is required")
	}
	keyID := queueauth.ResolveKeyID(*queueAuthKeyID, *queueAuthKeyIDEnv)
	criticalQueueCodec := queueauth.New(queueauth.Config{
		KeyID:  keyID,
		Secret: queueauth.ResolveSecret("", *queueAuthHMACEnv),
	})

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
		rec := auditRecord{
			Topic:         *topic,
			Critical:      queueauth.IsCriticalTopic(*topic),
			DryRun:        *dryRun,
			KeyID:         keyID,
			PayloadSHA256: sha256Hex(p),
			PayloadBytes:  len(p),
		}
		wirePayload, err := queueauth.WrapPayload(criticalQueueCodec, *topic, p)
		if err != nil {
			rec.Status = "rejected"
			rec.Error = err.Error()
			writeAuditRecord(stderr, rec)
			return err
		}
		rec.WireSHA256 = sha256Hex(wirePayload)
		rec.WireBytes = len(wirePayload)
		if *dryRun {
			rec.Status = "dry_run"
			writeAuditRecord(stderr, rec)
			continue
		}
		if err := producer.Publish(ctx, *topic, wirePayload); err != nil {
			rec.Status = "publish_failed"
			rec.Error = err.Error()
			writeAuditRecord(stderr, rec)
			return err
		}
		rec.Status = "published"
		writeAuditRecord(stderr, rec)
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

func writeAuditRecord(w io.Writer, rec auditRecord) {
	if w == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(rec)
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
