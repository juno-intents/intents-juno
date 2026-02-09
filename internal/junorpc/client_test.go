package junorpc

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
