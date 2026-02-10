package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_Send_SetsBearerAndParsesResponse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method: got %s want %s", r.Method, http.MethodPost)
		}
		if r.URL.Path != "/v1/send" {
			t.Fatalf("path: got %s want %s", r.URL.Path, "/v1/send")
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("Authorization: got %q want %q", got, "Bearer secret")
		}

		var req SendRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode req: %v", err)
		}
		if req.To != "0x0000000000000000000000000000000000000001" {
			t.Fatalf("To: got %s", req.To)
		}
		if req.Data != "0x0102" {
			t.Fatalf("Data: got %s", req.Data)
		}
		if req.ValueWei != "123" {
			t.Fatalf("ValueWei: got %s", req.ValueWei)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SendResponse{
			From:         "0x0000000000000000000000000000000000000002",
			Nonce:        7,
			TxHash:       "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Replacements: 0,
			Receipt: &ReceiptResponse{
				Status:      1,
				BlockNumber: "123",
				GasUsed:     555,
			},
		})
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient(srv.URL, "secret", WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	res, err := c.Send(ctx, SendRequest{
		To:       "0x0000000000000000000000000000000000000001",
		Data:     "0x0102",
		ValueWei: "123",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.TxHash == "" || res.TxHash[:2] != "0x" {
		t.Fatalf("TxHash: got %q", res.TxHash)
	}
	if res.Receipt == nil || res.Receipt.Status != 1 {
		t.Fatalf("Receipt: %+v", res.Receipt)
	}
}

func TestClient_Send_ReturnsErrorOnNon200(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient(srv.URL, "secret", WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = c.Send(context.Background(), SendRequest{To: "0x0000000000000000000000000000000000000001"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("401")) {
		t.Fatalf("error should contain status code: %v", err)
	}
}

