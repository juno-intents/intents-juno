package junoscanhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewWithTimeoutUsesConfiguredTimeout(t *testing.T) {
	t.Parallel()

	client := NewWithTimeout("http://127.0.0.1:8080", "", 75*time.Second)
	if got := client.hc.Timeout; got != 75*time.Second {
		t.Fatalf("timeout: got %s want %s", got, 75*time.Second)
	}
}

func TestListWalletNotesRequestsIncomingDirectionAndFiltersResponse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/wallets/wallet-a/notes" {
			t.Fatalf("path: got %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("limit"); got != "1000" {
			t.Fatalf("limit: got %q want 1000", got)
		}
		if got := r.URL.Query().Get("direction"); got != "incoming" {
			t.Fatalf("direction: got %q want incoming", got)
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"notes": []map[string]any{
				{
					"direction":    "outgoing",
					"txid":         "bad",
					"action_index": 0,
					"value_zat":    1,
					"height":       10,
				},
				{
					"direction":    "incoming",
					"txid":         "good",
					"action_index": 1,
					"value_zat":    2,
					"height":       11,
				},
			},
		})
	}))
	defer srv.Close()

	notes, err := New(srv.URL, "").ListWalletNotes(context.Background(), "wallet-a")
	if err != nil {
		t.Fatalf("ListWalletNotes: %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("notes len: got %d want 1: %#v", len(notes), notes)
	}
	if notes[0].TxID != "good" || notes[0].ActionIndex != 1 || notes[0].ValueZat != 2 || notes[0].Height != 11 {
		t.Fatalf("note: got %#v", notes[0])
	}
}

func TestOrchardWitnessRetriesExactBusyResponseUsingRetryAfter(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Retry-After", "7")
			http.Error(w, "witness busy", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"anchor_height": 42,
			"root":          "0x1234",
			"paths":         []any{},
		})
	}))
	defer srv.Close()

	client := NewWithTimeout(srv.URL, "", time.Minute)
	var waited time.Duration
	client.wait = func(_ context.Context, delay time.Duration) error {
		waited = delay
		return nil
	}

	got, err := client.OrchardWitness(context.Background(), nil, []uint32{7})
	if err != nil {
		t.Fatalf("OrchardWitness: %v", err)
	}
	if got.AnchorHeight != 42 {
		t.Fatalf("anchor height: got %d want 42", got.AnchorHeight)
	}
	if gotRequests := requests.Load(); gotRequests != 2 {
		t.Fatalf("requests: got %d want 2", gotRequests)
	}
	if waited != 7*time.Second {
		t.Fatalf("retry delay: got %s want 7s", waited)
	}
}

func TestOrchardWitnessDoesNotRetryOtherServiceUnavailable(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Retry-After", "7")
		http.Error(w, "scanner unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := NewWithTimeout(srv.URL, "", time.Minute)
	client.wait = func(context.Context, time.Duration) error {
		t.Fatal("unexpected retry")
		return nil
	}

	_, err := client.OrchardWitness(context.Background(), nil, []uint32{7})
	if err == nil || !strings.Contains(err.Error(), "scanner unavailable") {
		t.Fatalf("error: got %v want scanner unavailable", err)
	}
	if gotRequests := requests.Load(); gotRequests != 1 {
		t.Fatalf("requests: got %d want 1", gotRequests)
	}
}

func TestOrchardWitnessCancellationInterruptsBusyBackoff(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Retry-After", "600")
		http.Error(w, "witness busy", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := NewWithTimeout(srv.URL, "", time.Minute)
	enteredBackoff := make(chan struct{})
	client.wait = func(ctx context.Context, delay time.Duration) error {
		if delay != 10*time.Minute {
			t.Fatalf("retry delay: got %s want 10m", delay)
		}
		close(enteredBackoff)
		return waitForRetry(ctx, delay)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-enteredBackoff
		cancel()
	}()

	_, err := client.OrchardWitness(ctx, nil, []uint32{7})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error: got %v want %v", err, context.Canceled)
	}
	if gotRequests := requests.Load(); gotRequests != 1 {
		t.Fatalf("requests: got %d want 1", gotRequests)
	}
}
