package junoscanhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
