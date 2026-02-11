package tsshost

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/juno-intents/intents-juno/internal/tss"
)

func TestExecSigner_Sign_Success(t *testing.T) {
	t.Parallel()

	s, err := NewExecSigner("fake-signer", 1<<20)
	if err != nil {
		t.Fatalf("NewExecSigner: %v", err)
	}
	sessionID := [32]byte{0x01, 0x02}
	txPlan := []byte{0xaa, 0xbb}

	s.execFn = func(_ context.Context, bin string, stdin []byte) ([]byte, []byte, error) {
		if bin != "fake-signer" {
			t.Fatalf("bin: got %q want %q", bin, "fake-signer")
		}
		var req tss.SignRequest
		if err := json.Unmarshal(stdin, &req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Version != tss.SignRequestVersion {
			t.Fatalf("request version: got %q want %q", req.Version, tss.SignRequestVersion)
		}
		if req.SessionID != tss.FormatSessionID(sessionID) {
			t.Fatalf("request session id mismatch")
		}
		if len(req.TxPlan) != 2 {
			t.Fatalf("request txplan length mismatch")
		}
		resp, _ := json.Marshal(tss.SignResponse{
			Version:   tss.SignResponseVersion,
			SessionID: tss.FormatSessionID(sessionID),
			SignedTx:  []byte{0x10, 0x20},
		})
		return resp, nil, nil
	}

	got, err := s.Sign(context.Background(), sessionID, txPlan)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(got) != 2 || got[0] != 0x10 || got[1] != 0x20 {
		t.Fatalf("signed tx mismatch: %x", got)
	}
}

func TestExecSigner_Sign_PropagatesCommandError(t *testing.T) {
	t.Parallel()

	s, err := NewExecSigner("fake-signer", 1<<20)
	if err != nil {
		t.Fatalf("NewExecSigner: %v", err)
	}
	s.execFn = func(_ context.Context, _ string, _ []byte) ([]byte, []byte, error) {
		return nil, []byte("bad"), errors.New("exit 1")
	}

	_, err = s.Sign(context.Background(), [32]byte{0x01}, []byte{0xaa})
	if err == nil || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}

func TestNewExecSigner_RejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	_, err := NewExecSigner("", 1<<20)
	if !errors.Is(err, ErrInvalidExecSignerConfig) {
		t.Fatalf("expected ErrInvalidExecSignerConfig, got %v", err)
	}
}
