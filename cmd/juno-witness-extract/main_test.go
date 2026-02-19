package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/juno-intents/intents-juno/internal/proverinput"
)

func TestRunMain_Deposit_WritesWitnessFileAndStdoutJSON(t *testing.T) {
	txid := "39abd5a44a45b46c913e3d5ed1da22b25f08db8b9c3e52a3dbc9f4e23944998e"
	rootHex := "0x" + strings.Repeat("99", 32)

	scanSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/wallets/wallet-a/notes"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"notes": []map[string]any{
					{
						"txid":         txid,
						"action_index": 1,
						"position":     7,
					},
				},
				"next_cursor": "",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/orchard/witness":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":        "ok",
				"anchor_height": 120,
				"root":          rootHex,
				"paths": []map[string]any{
					{
						"position": 7,
						"auth_path": func() []string {
							out := make([]string, 32)
							for i := range out {
								b := make([]byte, 32)
								b[0] = byte(i + 1)
								out[i] = "0x" + hexutil.Encode(b)[2:]
							}
							return out
						}(),
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer scanSrv.Close()

	rawHex := strings.Repeat("ab", 100)
	rpcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode rpc request: %v", err)
		}
		method, _ := req["method"].(string)
		id := req["id"]
		switch method {
		case "getrawtransaction":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": rawHex,
				"error":  nil,
				"id":     id,
			})
		case "decoderawtransaction":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": map[string]any{
					"orchard": map[string]any{
						"actions": []map[string]any{
							{
								"nullifier":     strings.Repeat("11", 32),
								"rk":            strings.Repeat("22", 32),
								"cmx":           strings.Repeat("33", 32),
								"ephemeralKey":  strings.Repeat("44", 32),
								"encCiphertext": strings.Repeat("55", 580),
								"outCiphertext": strings.Repeat("66", 80),
								"cv":            strings.Repeat("77", 32),
							},
							{
								"nullifier":     strings.Repeat("aa", 32),
								"rk":            strings.Repeat("bb", 32),
								"cmx":           strings.Repeat("cc", 32),
								"ephemeralKey":  strings.Repeat("dd", 32),
								"encCiphertext": strings.Repeat("ee", 580),
								"outCiphertext": strings.Repeat("ff", 80),
								"cv":            strings.Repeat("99", 32),
							},
						},
					},
				},
				"error": nil,
				"id":    id,
			})
		default:
			t.Fatalf("unexpected rpc method: %s", method)
		}
	}))
	defer rpcSrv.Close()

	t.Setenv("JUNO_RPC_USER", "rpcuser")
	t.Setenv("JUNO_RPC_PASS", "rpcpass")

	tmp := t.TempDir()
	witnessPath := filepath.Join(tmp, "deposit.witness.bin")

	var stdout bytes.Buffer
	err := runMain([]string{
		"deposit",
		"--juno-scan-url", scanSrv.URL,
		"--wallet-id", "wallet-a",
		"--juno-rpc-url", rpcSrv.URL,
		"--txid", txid,
		"--action-index", "1",
		"--output-witness-item-file", witnessPath,
	}, &stdout)
	if err != nil {
		t.Fatalf("runMain: %v", err)
	}

	gotBytes, err := os.ReadFile(witnessPath)
	if err != nil {
		t.Fatalf("read witness file: %v", err)
	}
	if len(gotBytes) != proverinput.DepositWitnessItemLen {
		t.Fatalf("witness len mismatch: got=%d want=%d", len(gotBytes), proverinput.DepositWitnessItemLen)
	}

	var out struct {
		FinalOrchardRoot string `json:"final_orchard_root"`
		Position         uint32 `json:"position"`
		WitnessItemHex   string `json:"witness_item_hex"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal stdout: %v", err)
	}
	if out.FinalOrchardRoot != rootHex {
		t.Fatalf("root mismatch: got=%s want=%s", out.FinalOrchardRoot, rootHex)
	}
	if out.Position != 7 {
		t.Fatalf("position mismatch: got=%d want=7", out.Position)
	}
	if out.WitnessItemHex == "" {
		t.Fatalf("witness_item_hex missing")
	}
}
