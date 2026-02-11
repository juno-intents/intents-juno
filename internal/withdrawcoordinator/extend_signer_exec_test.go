package withdrawcoordinator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestExecExtendSigner_SignExtendDigest(t *testing.T) {
	t.Parallel()

	digest := common.HexToHash("0x096b6960ecac1de01b1d37dea33c1b774f83c442c9a69e0c84b0f90ef0fbfef8")
	wantSig := make([]byte, 65)
	wantSig[64] = 27

	s, err := NewExecExtendSigner("juno-txsign", 1<<20)
	if err != nil {
		t.Fatalf("NewExecExtendSigner: %v", err)
	}

	s.execCommand = func(_ context.Context, bin string, args []string) ([]byte, []byte, error) {
		if bin != "juno-txsign" {
			t.Fatalf("bin: got %q want %q", bin, "juno-txsign")
		}
		wantArgs := []string{"sign-digest", "--digest", digest.Hex(), "--json"}
		if !slices.Equal(args, wantArgs) {
			t.Fatalf("args: got %v want %v", args, wantArgs)
		}

		sigHex := "0x" + hex.EncodeToString(wantSig)
		resp, err := json.Marshal(map[string]any{
			"version": execExtendSignJSONVersion,
			"status":  "ok",
			"data": map[string]any{
				"signatures": []string{sigHex},
			},
		})
		if err != nil {
			t.Fatalf("marshal response: %v", err)
		}
		return resp, nil, nil
	}

	sigs, err := s.SignExtendDigest(context.Background(), digest)
	if err != nil {
		t.Fatalf("SignExtendDigest: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("signature count: got %d want 1", len(sigs))
	}
	if len(sigs[0]) != len(wantSig) {
		t.Fatalf("signature length: got %d want %d", len(sigs[0]), len(wantSig))
	}
	if sigs[0][64] != wantSig[64] {
		t.Fatalf("signature v: got %d want %d", sigs[0][64], wantSig[64])
	}
}

func TestExecExtendSigner_SignExtendDigest_RejectsBadSignature(t *testing.T) {
	t.Parallel()

	s, err := NewExecExtendSigner("juno-txsign", 1<<20)
	if err != nil {
		t.Fatalf("NewExecExtendSigner: %v", err)
	}
	s.execCommand = func(_ context.Context, _ string, _ []string) ([]byte, []byte, error) {
		return []byte(`{"version":"v1","status":"ok","data":{"signatures":["0x01"]}}`), nil, nil
	}

	_, err = s.SignExtendDigest(context.Background(), common.HexToHash("0x1"))
	if err == nil {
		t.Fatalf("expected error")
	}
}
