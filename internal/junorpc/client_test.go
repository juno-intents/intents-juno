package junorpc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func TestClient_GetBlockChainInfo_ParsesBlocks(t *testing.T) {
	t.Parallel()

	const (
		user = "rpcuser"
		pass = "rpcpass"
	)
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Errorf("Authorization header mismatch: got %q want %q", got, wantAuth)
		}
		if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
			t.Errorf("Content-Type mismatch: got %q", got)
		}

		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "getblockchaininfo" {
			t.Fatalf("method: got %q want %q", req.Method, "getblockchaininfo")
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{"blocks": 4242},
			"error":  nil,
			"id":     req.ID,
		})
	}))
	defer srv.Close()

	c, err := New(srv.URL, user, pass,
		WithHTTPClient(srv.Client()),
		WithTimeout(2*time.Second),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	info, err := c.GetBlockChainInfo(ctx)
	if err != nil {
		t.Fatalf("GetBlockChainInfo: %v", err)
	}
	if info.Blocks != 4242 {
		t.Fatalf("blocks: got %d want %d", info.Blocks, 4242)
	}
}

func TestClient_GetBlockHash_ParsesHash(t *testing.T) {
	t.Parallel()

	const (
		user = "rpcuser"
		pass = "rpcpass"
	)

	want := common.HexToHash("0x39abd5a44a45b46c913e3d5ed1da22b25f08db8b9c3e52a3dbc9f4e23944998e")
	wantRPC := strings.TrimPrefix(want.Hex(), "0x") // junocashd returns hashes without 0x

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "getblockhash" {
			t.Fatalf("method: got %q want %q", req.Method, "getblockhash")
		}
		if len(req.Params) != 1 || req.Params[0] != float64(7) {
			t.Fatalf("params: got %#v want [7]", req.Params)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": wantRPC,
			"error":  nil,
			"id":     req.ID,
		})
	}))
	defer srv.Close()

	c, err := New(srv.URL, user, pass, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got, err := c.GetBlockHash(ctx, 7)
	if err != nil {
		t.Fatalf("GetBlockHash: %v", err)
	}
	if got != want {
		t.Fatalf("hash mismatch: got %s want %s", got, want)
	}
}

func TestClient_GetBlock_ParsesFinalOrchardRoot(t *testing.T) {
	t.Parallel()

	const (
		user = "rpcuser"
		pass = "rpcpass"
	)

	blockHash := common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091")
	finalRoot := common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "getblock" {
			t.Fatalf("method: got %q want %q", req.Method, "getblock")
		}
		if len(req.Params) != 2 {
			t.Fatalf("params: got %#v want 2 items", req.Params)
		}
		if req.Params[0] != strings.TrimPrefix(blockHash.Hex(), "0x") {
			t.Fatalf("hash param mismatch: got %v want %v", req.Params[0], strings.TrimPrefix(blockHash.Hex(), "0x"))
		}
		if req.Params[1] != float64(1) {
			t.Fatalf("verbosity param mismatch: got %v want %v", req.Params[1], float64(1))
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"hash":             strings.TrimPrefix(blockHash.Hex(), "0x"),
				"height":           123,
				"finalorchardroot": strings.TrimPrefix(finalRoot.Hex(), "0x"),
			},
			"error": nil,
			"id":    req.ID,
		})
	}))
	defer srv.Close()

	c, err := New(srv.URL, user, pass, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	b, err := c.GetBlock(ctx, blockHash)
	if err != nil {
		t.Fatalf("GetBlock: %v", err)
	}
	if b.Hash != blockHash {
		t.Fatalf("hash mismatch: got %s want %s", b.Hash, blockHash)
	}
	if b.Height != 123 {
		t.Fatalf("height mismatch: got %d want %d", b.Height, 123)
	}
	if b.FinalOrchardRoot != finalRoot {
		t.Fatalf("finalOrchardRoot mismatch: got %s want %s", b.FinalOrchardRoot, finalRoot)
	}
}

func TestClient_SendRawTransaction(t *testing.T) {
	t.Parallel()

	const (
		user = "rpcuser"
		pass = "rpcpass"
	)

	wantTxID := "39abd5a44a45b46c913e3d5ed1da22b25f08db8b9c3e52a3dbc9f4e23944998e"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "sendrawtransaction" {
			t.Fatalf("method: got %q want %q", req.Method, "sendrawtransaction")
		}
		if len(req.Params) != 1 {
			t.Fatalf("params: got %#v want 1 item", req.Params)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": wantTxID,
			"error":  nil,
			"id":     req.ID,
		})
	}))
	defer srv.Close()

	c, err := New(srv.URL, user, pass, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	txid, err := c.SendRawTransaction(context.Background(), []byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("SendRawTransaction: %v", err)
	}
	if txid != wantTxID {
		t.Fatalf("txid mismatch: got %q want %q", txid, wantTxID)
	}
}

func TestClient_GetRawTransaction_ParsesConfirmations(t *testing.T) {
	t.Parallel()

	const (
		user = "rpcuser"
		pass = "rpcpass"
	)

	wantTxID := "39abd5a44a45b46c913e3d5ed1da22b25f08db8b9c3e52a3dbc9f4e23944998e"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "getrawtransaction" {
			t.Fatalf("method: got %q want %q", req.Method, "getrawtransaction")
		}
		if len(req.Params) != 2 {
			t.Fatalf("params: got %#v want 2 items", req.Params)
		}
		if req.Params[1] != float64(1) {
			t.Fatalf("verbosity param mismatch: got %v want %v", req.Params[1], float64(1))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"txid":          wantTxID,
				"confirmations": 7,
			},
			"error": nil,
			"id":    req.ID,
		})
	}))
	defer srv.Close()

	c, err := New(srv.URL, user, pass, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.GetRawTransaction(context.Background(), "0x"+wantTxID)
	if err != nil {
		t.Fatalf("GetRawTransaction: %v", err)
	}
	if res.TxID != wantTxID {
		t.Fatalf("txid mismatch: got %q want %q", res.TxID, wantTxID)
	}
	if res.Confirmations != 7 {
		t.Fatalf("confirmations mismatch: got %d want %d", res.Confirmations, 7)
	}
}

func TestClient_GetRawTransaction_MapsNotFound(t *testing.T) {
	t.Parallel()

	const (
		user = "rpcuser"
		pass = "rpcpass"
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": nil,
			"error": map[string]any{
				"code":    -5,
				"message": "No such mempool or blockchain transaction",
			},
			"id": req.ID,
		})
	}))
	defer srv.Close()

	c, err := New(srv.URL, user, pass, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = c.GetRawTransaction(context.Background(), "39abd5a44a45b46c913e3d5ed1da22b25f08db8b9c3e52a3dbc9f4e23944998e")
	if !errors.Is(err, ErrTxNotFound) {
		t.Fatalf("expected ErrTxNotFound, got %v", err)
	}
}

func TestClient_GetOrchardAction_DecodesFromDecodeRawTransaction(t *testing.T) {
	t.Parallel()

	const (
		user = "rpcuser"
		pass = "rpcpass"
	)

	txid := "39abd5a44a45b46c913e3d5ed1da22b25f08db8b9c3e52a3dbc9f4e23944998e"
	rawHex := strings.Repeat("ab", 100)

	nullifierHex := strings.Repeat("11", 32)
	rkHex := strings.Repeat("22", 32)
	cmxHex := strings.Repeat("33", 32)
	epkHex := strings.Repeat("44", 32)
	cvHex := strings.Repeat("55", 32)
	encHex := strings.Repeat("66", 580)
	outHex := strings.Repeat("77", 80)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		switch req.Method {
		case "getrawtransaction":
			if len(req.Params) != 1 {
				t.Fatalf("getrawtransaction params: got %#v want [txid]", req.Params)
			}
			if req.Params[0] != txid {
				t.Fatalf("getrawtransaction txid param: got %v want %v", req.Params[0], txid)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": rawHex,
				"error":  nil,
				"id":     req.ID,
			})
			return
		case "decoderawtransaction":
			if len(req.Params) != 1 || req.Params[0] != rawHex {
				t.Fatalf("decoderawtransaction params: got %#v want [%q]", req.Params, rawHex)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": map[string]any{
					"orchard": map[string]any{
						"actions": []map[string]any{
							{
								"nullifier":     nullifierHex,
								"rk":            rkHex,
								"cmx":           cmxHex,
								"ephemeralKey":  epkHex,
								"encCiphertext": encHex,
								"outCiphertext": outHex,
								"cv":            cvHex,
							},
						},
					},
				},
				"error": nil,
				"id":    req.ID,
			})
			return
		default:
			t.Fatalf("unexpected method: %q", req.Method)
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL, user, pass, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := c.GetOrchardAction(context.Background(), txid, 0)
	if err != nil {
		t.Fatalf("GetOrchardAction: %v", err)
	}

	if got.Nullifier[0] != 0x11 {
		t.Fatalf("nullifier[0] mismatch: got=%x want=11", got.Nullifier[0])
	}
	if got.RK[0] != 0x22 {
		t.Fatalf("rk[0] mismatch: got=%x want=22", got.RK[0])
	}
	if got.CMX[0] != 0x33 {
		t.Fatalf("cmx[0] mismatch: got=%x want=33", got.CMX[0])
	}
	if got.EphemeralKey[0] != 0x44 {
		t.Fatalf("ephemeral_key[0] mismatch: got=%x want=44", got.EphemeralKey[0])
	}
	if got.CV[0] != 0x55 {
		t.Fatalf("cv[0] mismatch: got=%x want=55", got.CV[0])
	}
	if got.EncCiphertext[0] != 0x66 || got.EncCiphertext[len(got.EncCiphertext)-1] != 0x66 {
		t.Fatalf("enc ciphertext decode mismatch")
	}
	if got.OutCiphertext[0] != 0x77 || got.OutCiphertext[len(got.OutCiphertext)-1] != 0x77 {
		t.Fatalf("out ciphertext decode mismatch")
	}
}

func TestClient_GetOrchardAction_InvalidActionEncoding(t *testing.T) {
	t.Parallel()

	const (
		user = "rpcuser"
		pass = "rpcpass"
	)

	txid := "39abd5a44a45b46c913e3d5ed1da22b25f08db8b9c3e52a3dbc9f4e23944998e"
	rawHex := strings.Repeat("cd", 100)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		switch req.Method {
		case "getrawtransaction":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": rawHex,
				"error":  nil,
				"id":     req.ID,
			})
		case "decoderawtransaction":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": map[string]any{
					"orchard": map[string]any{
						"actions": []map[string]any{
							{
								"nullifier":     "zz", // invalid hex
								"rk":            strings.Repeat("22", 32),
								"cmx":           strings.Repeat("33", 32),
								"ephemeralKey":  strings.Repeat("44", 32),
								"encCiphertext": strings.Repeat("66", 580),
								"outCiphertext": strings.Repeat("77", 80),
								"cv":            strings.Repeat("55", 32),
							},
						},
					},
				},
				"error": nil,
				"id":    req.ID,
			})
		default:
			t.Fatalf("unexpected method: %q", req.Method)
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL, user, pass, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = c.GetOrchardAction(context.Background(), txid, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "nullifier") {
		t.Fatalf("unexpected error: %v", err)
	}
}
