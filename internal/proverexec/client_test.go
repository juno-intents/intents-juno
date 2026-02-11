package proverexec

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestClient_Prove_Success(t *testing.T) {
	t.Parallel()

	c, err := New("fake-prover", 1<<20)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	c.execCommand = func(_ context.Context, bin string, stdin []byte) ([]byte, []byte, error) {
		if bin != "fake-prover" {
			t.Fatalf("bin: got %q want %q", bin, "fake-prover")
		}
		var req map[string]any
		if err := json.Unmarshal(stdin, &req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req["version"] != "prover.request.v1" {
			t.Fatalf("version: got %v", req["version"])
		}
		if req["privateInput"] != "0x0304" {
			t.Fatalf("privateInput: got %v want 0x0304", req["privateInput"])
		}
		return []byte(`{"version":"prover.response.v1","seal":"0x0102"}`), nil, nil
	}

	seal, err := c.Prove(context.Background(), common.HexToHash("0x01"), []byte{0xaa, 0xbb}, []byte{0x03, 0x04})
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if len(seal) != 2 || seal[0] != 0x01 || seal[1] != 0x02 {
		t.Fatalf("unexpected seal: %x", seal)
	}
}

func TestClient_Prove_PropagatesCommandError(t *testing.T) {
	t.Parallel()

	c, err := New("fake-prover", 1<<20)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.execCommand = func(_ context.Context, _ string, _ []byte) ([]byte, []byte, error) {
		return nil, []byte("boom"), errors.New("exit 1")
	}

	_, err = c.Prove(context.Background(), common.HexToHash("0x01"), []byte{0xaa}, nil)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}

func TestClient_Prove_RejectsErrorEnvelope(t *testing.T) {
	t.Parallel()

	c, err := New("fake-prover", 1<<20)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.execCommand = func(_ context.Context, _ string, _ []byte) ([]byte, []byte, error) {
		return []byte(`{"version":"prover.response.v1","error":"upstream failed"}`), nil, nil
	}

	_, err = c.Prove(context.Background(), common.HexToHash("0x01"), []byte{0xaa}, nil)
	if err == nil || !strings.Contains(err.Error(), "upstream failed") {
		t.Fatalf("expected response error, got %v", err)
	}
}

func TestNew_RejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	_, err := New("", 1)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
}
