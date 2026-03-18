package junoscanhttp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNotesFilterProxyServeHTTP_FiltersOutgoingWalletNotes(t *testing.T) {
	t.Parallel()

	var gotAuthHeader, gotRequestPath, gotRequestQuery string
	handler := newNotesFilterProxyHandler("http://scan.internal/base", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			gotAuthHeader = r.Header.Get("Authorization")
			gotRequestPath = r.URL.Path
			gotRequestQuery = r.URL.RawQuery
			return jsonResponse(http.StatusOK, `{
				"notes": [
					{"direction":"outgoing","txid":"bad","action_index":0,"value_zat":1},
					{"direction":"incoming","txid":"good","action_index":1,"value_zat":2},
					{"txid":"legacy","action_index":2,"value_zat":3}
				],
				"next_cursor": "cursor-1"
			}`), nil
		}),
	})
	req := httptest.NewRequest(http.MethodGet, "http://proxy/v1/wallets/wallet-a/notes?limit=1000", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	resp := rr.Result()
	defer resp.Body.Close()
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Fatalf("status code: got %d want %d", got, want)
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

	if gotAuthHeader != "Bearer test-token" {
		t.Fatalf("upstream auth header: got %q want %q", gotAuthHeader, "Bearer test-token")
	}
	if gotRequestPath != "/base/v1/wallets/wallet-a/notes" {
		t.Fatalf("upstream path: got %q want %q", gotRequestPath, "/base/v1/wallets/wallet-a/notes")
	}
	if gotRequestQuery != "limit=1000" {
		t.Fatalf("upstream query: got %q want %q", gotRequestQuery, "limit=1000")
	}
}

func TestNotesFilterProxyServeHTTP_PassesThroughNonNoteResponses(t *testing.T) {
	t.Parallel()

	var gotMethod string
	handler := newNotesFilterProxyHandler("http://scan.internal", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			gotMethod = r.Method
			return jsonResponse(http.StatusAccepted, `{"status":"ok","scanned_height":123}`), nil
		}),
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy/v1/health", io.NopCloser(strings.NewReader(`{"status":"ping"}`)))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	resp := rr.Result()
	defer resp.Body.Close()
	if got, want := resp.StatusCode, http.StatusAccepted; got != want {
		t.Fatalf("status: got %d want %d", got, want)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(raw) != `{"status":"ok","scanned_height":123}` {
		t.Fatalf("body: got %q want %q", string(raw), `{"status":"ok","scanned_height":123}`)
	}
	if got, want := gotMethod, http.MethodPost; got != want {
		t.Fatalf("method: got %q want %q", got, want)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}
}
