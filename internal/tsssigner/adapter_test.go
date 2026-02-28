package tsssigner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAdapter_Sign_Success(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	sessionID := [32]byte{0x01, 0x02, 0x03}
	txPlan := []byte(`{"version":"v0"}`)

	type invocation struct {
		bin  string
		args []string
	}
	var got []invocation

	a, err := NewAdapter(Config{
		TxSignBin:          "juno-txsign",
		UFVK:               "jviewregtest1example",
		SpendAuthSignerBin: "dkg-signer",
		WorkDir:            tmpDir,
		Exec: func(_ context.Context, bin string, args []string, _ []byte) ([]byte, []byte, error) {
			got = append(got, invocation{bin: bin, args: append([]string(nil), args...)})

			switch {
			case bin == "juno-txsign" && len(args) > 0 && args[0] == "ext-prepare":
				preparedPath := argValue(args, "--out-prepared")
				requestsPath := argValue(args, "--out-requests")
				if preparedPath == "" || requestsPath == "" {
					t.Fatalf("missing output paths in ext-prepare args: %v", args)
				}
				if err := os.WriteFile(preparedPath, []byte(`{"version":"v0","orchard_pczt":{"actions":[{},{}]}}`), 0o600); err != nil {
					t.Fatalf("write prepared: %v", err)
				}
				if err := os.WriteFile(requestsPath, []byte(`{"version":"v0","requests":[{"sighash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","action_index":0,"alpha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rk":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]}`), 0o600); err != nil {
					t.Fatalf("write requests: %v", err)
				}
				return []byte(`{"version":"v1","status":"ok","data":{"prepared_tx":{"version":"v0"},"signing_requests":{"version":"v0","requests":[{"sighash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","action_index":0,"alpha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rk":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]}}}`), nil, nil

			case bin == "dkg-signer":
				sigsPath := argValue(args, "--out")
				if sigsPath == "" {
					t.Fatalf("missing sigs path in signer args: %v", args)
				}
				if err := os.WriteFile(sigsPath, []byte(`{"version":"v0","signatures":[{"action_index":0,"spend_auth_sig":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]}`), 0o600); err != nil {
					t.Fatalf("write sigs: %v", err)
				}
				return []byte(`ok`), nil, nil

			case bin == "juno-txsign" && len(args) > 0 && args[0] == "ext-finalize":
				return []byte(`{"version":"v1","status":"ok","data":{"txid":"aa","raw_tx_hex":"00ff","fee_zat":"1000"}}`), nil, nil

			default:
				t.Fatalf("unexpected invocation: %s %v", bin, args)
				return nil, nil, nil
			}
		},
	})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}

	raw, err := a.Sign(context.Background(), sessionID, txPlan)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !slices.Equal(raw, []byte{0x00, 0xff}) {
		t.Fatalf("raw tx mismatch: got %x want 00ff", raw)
	}

	if len(got) != 3 {
		t.Fatalf("invocation count: got %d want 3", len(got))
	}
	if got[0].bin != "juno-txsign" || got[0].args[0] != "ext-prepare" {
		t.Fatalf("first invocation mismatch: %+v", got[0])
	}
	if got[1].bin != "dkg-signer" || got[1].args[0] != "sign-spendauth" {
		t.Fatalf("second invocation mismatch: %+v", got[1])
	}
	if got[2].bin != "juno-txsign" || got[2].args[0] != "ext-finalize" {
		t.Fatalf("third invocation mismatch: %+v", got[2])
	}
}

func TestAdapter_Sign_RejectsInvalidSpendAuthSignerOutput(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	a, err := NewAdapter(Config{
		TxSignBin:          "juno-txsign",
		UFVK:               "jviewregtest1example",
		SpendAuthSignerBin: "dkg-signer",
		WorkDir:            tmpDir,
		Exec: func(_ context.Context, bin string, args []string, _ []byte) ([]byte, []byte, error) {
			switch {
			case bin == "juno-txsign" && len(args) > 0 && args[0] == "ext-prepare":
				_ = os.WriteFile(argValue(args, "--out-prepared"), []byte(`{"version":"v0","orchard_pczt":{"actions":[{},{}]}}`), 0o600)
				_ = os.WriteFile(argValue(args, "--out-requests"), []byte(`{"version":"v0","requests":[{"sighash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","action_index":0,"alpha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rk":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]}`), 0o600)
				return []byte(`{"version":"v1","status":"ok","data":{"prepared_tx":{"version":"v0"},"signing_requests":{"version":"v0","requests":[{"sighash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","action_index":0,"alpha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rk":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]}}}`), nil, nil
			case bin == "dkg-signer":
				// Wrong schema: missing spend_auth_sig.
				_ = os.WriteFile(argValue(args, "--out"), []byte(`{"version":"v0","signatures":[{"action_index":0}]}`), 0o600)
				return []byte(`ok`), nil, nil
			default:
				return nil, nil, errors.New("should not run finalize")
			}
		},
	})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}

	_, err = a.Sign(context.Background(), [32]byte{0x99}, []byte(`{"version":"v0"}`))
	if err == nil || !strings.Contains(err.Error(), "invalid spend-auth signatures") {
		t.Fatalf("expected invalid spend-auth signatures error, got %v", err)
	}
}

func TestAdapter_Sign_RejectsFinalizeErrorEnvelope(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	a, err := NewAdapter(Config{
		TxSignBin:          "juno-txsign",
		UFVK:               "jviewregtest1example",
		SpendAuthSignerBin: "dkg-signer",
		WorkDir:            tmpDir,
		Exec: func(_ context.Context, bin string, args []string, _ []byte) ([]byte, []byte, error) {
			switch {
			case bin == "juno-txsign" && len(args) > 0 && args[0] == "ext-prepare":
				_ = os.WriteFile(argValue(args, "--out-prepared"), []byte(`{"version":"v0","orchard_pczt":{"actions":[{},{}]}}`), 0o600)
				_ = os.WriteFile(argValue(args, "--out-requests"), []byte(`{"version":"v0","requests":[{"sighash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","action_index":0,"alpha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rk":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]}`), 0o600)
				return []byte(`{"version":"v1","status":"ok","data":{"prepared_tx":{"version":"v0"},"signing_requests":{"version":"v0","requests":[{"sighash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","action_index":0,"alpha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rk":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]}}}`), nil, nil
			case bin == "dkg-signer":
				_ = os.WriteFile(argValue(args, "--out"), []byte(`{"version":"v0","signatures":[{"action_index":0,"spend_auth_sig":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]}`), 0o600)
				return []byte(`ok`), nil, nil
			case bin == "juno-txsign" && len(args) > 0 && args[0] == "ext-finalize":
				return []byte(`{"version":"v1","status":"err","error":{"code":"finalize_failed","message":"bad sig"}}`), nil, nil
			default:
				t.Fatalf("unexpected invocation: %s %v", bin, args)
				return nil, nil, nil
			}
		},
	})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}

	_, err = a.Sign(context.Background(), [32]byte{0x12}, []byte(`{"version":"v0"}`))
	if err == nil || !strings.Contains(err.Error(), "finalize_failed") {
		t.Fatalf("expected finalize_failed in error, got %v", err)
	}
}

func TestAdapter_Sign_DerivesSpendAuthSessionFromRequests(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	sessionID := [32]byte{0xaa, 0xbb, 0xcc}

	const requestsA = `{"version":"v0","requests":[{"sighash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","action_index":0,"alpha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rk":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]}`
	const requestsB = `{"version":"v0","requests":[{"sighash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","action_index":0,"alpha":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","rk":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}]}`

	prepareCalls := 0
	var signSessions []string
	firstSession := ""

	a, err := NewAdapter(Config{
		TxSignBin:          "juno-txsign",
		UFVK:               "jviewregtest1example",
		SpendAuthSignerBin: "dkg-signer",
		WorkDir:            tmpDir,
		Exec: func(_ context.Context, bin string, args []string, _ []byte) ([]byte, []byte, error) {
			switch {
			case bin == "juno-txsign" && len(args) > 0 && args[0] == "ext-prepare":
				preparedPath := argValue(args, "--out-prepared")
				requestsPath := argValue(args, "--out-requests")
				if preparedPath == "" || requestsPath == "" {
					t.Fatalf("missing output paths in ext-prepare args: %v", args)
				}
				if err := os.WriteFile(preparedPath, []byte(`{"version":"v0","orchard_pczt":{"actions":[{},{}]}}`), 0o600); err != nil {
					t.Fatalf("write prepared: %v", err)
				}
				payload := requestsA
				if prepareCalls > 0 {
					payload = requestsB
				}
				prepareCalls++
				if err := os.WriteFile(requestsPath, []byte(payload), 0o600); err != nil {
					t.Fatalf("write requests: %v", err)
				}
				return []byte(`{"version":"v1","status":"ok","data":{"prepared_tx":{"version":"v0"},"signing_requests":{"version":"v0","requests":[{"sighash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","action_index":0,"alpha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rk":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]}}}`), nil, nil

			case bin == "dkg-signer" && len(args) > 0 && args[0] == "sign-spendauth":
				sessionArg := argValue(args, "--session-id")
				signSessions = append(signSessions, sessionArg)
				if firstSession == "" {
					firstSession = sessionArg
					return nil, []byte("session_conflict"), errors.New("exit status 1")
				}
				if sessionArg == firstSession {
					return nil, []byte("session_conflict"), errors.New("exit status 1")
				}
				sigsPath := argValue(args, "--out")
				if sigsPath == "" {
					t.Fatalf("missing sigs path in signer args: %v", args)
				}
				if err := os.WriteFile(sigsPath, []byte(`{"version":"v0","signatures":[{"action_index":0,"spend_auth_sig":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]}`), 0o600); err != nil {
					t.Fatalf("write sigs: %v", err)
				}
				return []byte(`ok`), nil, nil

			case bin == "juno-txsign" && len(args) > 0 && args[0] == "ext-finalize":
				return []byte(`{"version":"v1","status":"ok","data":{"txid":"aa","raw_tx_hex":"00ff","fee_zat":"1000"}}`), nil, nil

			default:
				t.Fatalf("unexpected invocation: %s %v", bin, args)
				return nil, nil, nil
			}
		},
	})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}

	if _, err := a.Sign(context.Background(), sessionID, []byte(`{"version":"v0"}`)); err == nil || !strings.Contains(err.Error(), "session_conflict") {
		t.Fatalf("expected session_conflict on first signing attempt, got %v", err)
	}

	raw, err := a.Sign(context.Background(), sessionID, []byte(`{"version":"v0"}`))
	if err != nil {
		t.Fatalf("second Sign: %v", err)
	}
	if !slices.Equal(raw, []byte{0x00, 0xff}) {
		t.Fatalf("raw tx mismatch: got %x want 00ff", raw)
	}
	if len(signSessions) != 2 {
		t.Fatalf("expected 2 spend-auth attempts, got %d", len(signSessions))
	}
	if signSessions[0] == signSessions[1] {
		t.Fatalf("expected distinct derived spend-auth session ids, got %q", signSessions[0])
	}
}

func TestNewAdapter_RejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	_, err := NewAdapter(Config{})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func argValue(args []string, key string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key {
			return args[i+1]
		}
	}
	return ""
}

func TestValidateSpendAuthSubmission(t *testing.T) {
	t.Parallel()

	var s spendAuthSigSubmission
	if err := json.Unmarshal([]byte(`{"version":"v0","signatures":[{"action_index":1,"spend_auth_sig":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]}`), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := validateSpendAuthSubmission(s); err != nil {
		t.Fatalf("validate: %v", err)
	}

	s.Signatures[0].SpendAuthSig = "00"
	if err := validateSpendAuthSubmission(s); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBuildPaths_UniqueSessionDir(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	p := buildPaths(tmp, [32]byte{0xaa, 0xbb})
	if !strings.Contains(filepath.Base(p.dir), "aabb") {
		t.Fatalf("dir %q does not include session prefix", p.dir)
	}
}
