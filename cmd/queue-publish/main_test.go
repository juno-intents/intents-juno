package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/juno-intents/intents-juno/internal/queueauth"
)

func TestLoadPayloads_Inline(t *testing.T) {
	t.Parallel()

	payloads, err := loadPayloads(`{"version":"v1"}`, nil, nil)
	if err != nil {
		t.Fatalf("loadPayloads: %v", err)
	}
	if len(payloads) != 1 {
		t.Fatalf("payload count: got=%d want=1", len(payloads))
	}
	if string(payloads[0]) != `{"version":"v1"}` {
		t.Fatalf("payload mismatch: %q", string(payloads[0]))
	}
}

func TestLoadPayloads_File(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	payloadPath := filepath.Join(tmpDir, "payload.json")
	if err := os.WriteFile(payloadPath, []byte(`{"version":"v2"}`), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	payloads, err := loadPayloads("", []string{payloadPath}, nil)
	if err != nil {
		t.Fatalf("loadPayloads: %v", err)
	}
	if len(payloads) != 1 {
		t.Fatalf("payload count: got=%d want=1", len(payloads))
	}
	if string(payloads[0]) != `{"version":"v2"}` {
		t.Fatalf("payload mismatch: %q", string(payloads[0]))
	}
}

func TestLoadPayloads_StdinFallback(t *testing.T) {
	t.Parallel()

	payloads, err := loadPayloads("", nil, bytes.NewBufferString(`{"version":"v3"}`))
	if err != nil {
		t.Fatalf("loadPayloads: %v", err)
	}
	if len(payloads) != 1 {
		t.Fatalf("payload count: got=%d want=1", len(payloads))
	}
	if string(payloads[0]) != `{"version":"v3"}` {
		t.Fatalf("payload mismatch: %q", string(payloads[0]))
	}
}

func TestLoadPayloads_EmptyInput(t *testing.T) {
	t.Parallel()

	_, err := loadPayloads("", nil, bytes.NewBufferString(" \n\t"))
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestRunMain_StdioPublishesLines(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runMain(
		[]string{
			"--queue-driver", "stdio",
			"--topic", "example.topic",
			"--payload", `{"version":"v1"}`,
		},
		bytes.NewBuffer(nil),
		&out,
		&errOut,
	)
	if err != nil {
		t.Fatalf("runMain: %v", err)
	}
	if got := out.String(); got != "{\"version\":\"v1\"}\n" {
		t.Fatalf("unexpected stdout: %q", got)
	}
	if got := errOut.String(); got == "" {
		t.Fatal("expected audit log")
	}
}

func TestRunMain_SignsCriticalTopic(t *testing.T) {
	t.Setenv("QUEUE_AUTH_SECRET", "super-secret-key")

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runMain(
		[]string{
			"--queue-driver", "stdio",
			"--topic", "deposits.event.v2",
			"--payload", `{"version":"deposits.event.v2"}`,
			"--queue-auth-key-id", "ops-1",
			"--queue-auth-hmac-env", "QUEUE_AUTH_SECRET",
		},
		bytes.NewBuffer(nil),
		&out,
		&errOut,
	)
	if err != nil {
		t.Fatalf("runMain: %v", err)
	}
	codec := queueauth.New(queueauth.Config{
		KeyID:  "ops-1",
		Secret: []byte("super-secret-key"),
	})
	raw, err := codec.Unwrap("deposits.event.v2", bytes.TrimSpace(out.Bytes()))
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if got := string(raw); got != `{"version":"deposits.event.v2"}` {
		t.Fatalf("payload mismatch: %q", got)
	}
	if got := errOut.String(); got == "" {
		t.Fatal("expected audit log")
	}
}

func TestRunMain_RejectsUnsignedCriticalTopic(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runMain(
		[]string{
			"--queue-driver", "stdio",
			"--topic", "deposits.event.v2",
			"--payload", `{"version":"deposits.event.v2"}`,
		},
		bytes.NewBuffer(nil),
		&out,
		&errOut,
	)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunMain_DryRunSkipsPublish(t *testing.T) {
	t.Setenv("QUEUE_AUTH_SECRET", "super-secret-key")

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runMain(
		[]string{
			"--queue-driver", "stdio",
			"--topic", "deposits.event.v2",
			"--payload", `{"version":"deposits.event.v2"}`,
			"--queue-auth-key-id", "ops-1",
			"--queue-auth-hmac-env", "QUEUE_AUTH_SECRET",
			"--dry-run",
		},
		bytes.NewBuffer(nil),
		&out,
		&errOut,
	)
	if err != nil {
		t.Fatalf("runMain: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no publish output, got %q", out.String())
	}
	if got := errOut.String(); !bytes.Contains([]byte(got), []byte(`"status":"dry_run"`)) {
		t.Fatalf("expected dry_run audit record, got %q", got)
	}
}
