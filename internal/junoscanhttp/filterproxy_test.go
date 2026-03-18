package junoscanhttp

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestStartNotesFilterProxy_FiltersOutgoingWalletNotes(t *testing.T) {
	t.Parallel()

	var (
		mu              sync.Mutex
		gotAuthHeader   string
		gotRequestPath  string
		gotRequestQuery string
	)
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuthHeader = r.Header.Get("Authorization")
		gotRequestPath = r.URL.Path
		gotRequestQuery = r.URL.RawQuery
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"notes": [
				{"direction":"outgoing","txid":"bad","action_index":0,"value_zat":1},
				{"direction":"incoming","txid":"good","action_index":1,"value_zat":2},
				{"txid":"legacy","action_index":2,"value_zat":3}
			],
			"next_cursor": "cursor-1"
		}`)
	}))
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxy, err := StartNotesFilterProxy(ctx, upstream.URL)
	if err != nil {
		t.Fatalf("StartNotesFilterProxy: %v", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := proxy.Close(shutdownCtx); err != nil {
			t.Fatalf("proxy close: %v", err)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxy.BaseURL()+"/v1/wallets/wallet-a/notes?limit=1000", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code: got %d want %d", resp.StatusCode, http.StatusOK)
	}

	var body struct {
		Notes []struct {
			TxID string `json:"txid"`
		} `json:"notes"`
		NextCursor string `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode proxy response: %v", err)
	}

	if len(body.Notes) != 2 {
		t.Fatalf("notes len: got %d want 2", len(body.Notes))
	}
	if body.Notes[0].TxID != "good" {
		t.Fatalf("notes[0].txid: got %q want %q", body.Notes[0].TxID, "good")
	}
	if body.Notes[1].TxID != "legacy" {
		t.Fatalf("notes[1].txid: got %q want %q", body.Notes[1].TxID, "legacy")
	}
	if body.NextCursor != "cursor-1" {
		t.Fatalf("next_cursor: got %q want %q", body.NextCursor, "cursor-1")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotAuthHeader != "Bearer test-token" {
		t.Fatalf("upstream auth header: got %q want %q", gotAuthHeader, "Bearer test-token")
	}
	if gotRequestPath != "/v1/wallets/wallet-a/notes" {
		t.Fatalf("upstream path: got %q want %q", gotRequestPath, "/v1/wallets/wallet-a/notes")
	}
	if gotRequestQuery != "limit=1000" {
		t.Fatalf("upstream query: got %q want %q", gotRequestQuery, "limit=1000")
	}
}

func TestStartNotesFilterProxy_PassesThroughNonNoteResponses(t *testing.T) {
	t.Parallel()

	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","scanned_height":123}`)
	}))
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxy, err := StartNotesFilterProxy(ctx, upstream.URL)
	if err != nil {
		t.Fatalf("StartNotesFilterProxy: %v", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := proxy.Close(shutdownCtx); err != nil {
			t.Fatalf("proxy close: %v", err)
		}
	}()

	resp, err := http.Get(proxy.BaseURL() + "/v1/health")
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(raw) != `{"status":"ok","scanned_height":123}` {
		t.Fatalf("body: got %q want %q", string(raw), `{"status":"ok","scanned_height":123}`)
	}
}

type ipv4Server struct {
	URL    string
	server *http.Server
}

func (s *ipv4Server) Close() {
	if s == nil || s.server == nil {
		return
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = s.server.Shutdown(shutdownCtx)
}

func newIPv4Server(t *testing.T, handler http.Handler) *ipv4Server {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 127.0.0.1: %v", err)
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = server.Serve(listener)
	}()
	return &ipv4Server{
		URL:    "http://" + listener.Addr().String(),
		server: server,
	}
}
