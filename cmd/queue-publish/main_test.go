package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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
	err := runMain(
		[]string{
			"--queue-driver", "stdio",
			"--topic", "example.topic",
			"--payload", `{"version":"v1"}`,
		},
		bytes.NewBuffer(nil),
		&out,
	)
	if err != nil {
		t.Fatalf("runMain: %v", err)
	}
	if got := out.String(); got != "{\"version\":\"v1\"}\n" {
		t.Fatalf("unexpected stdout: %q", got)
	}
}
