package checkpoint

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPIPFSPinner_PinJSON(t *testing.T) {
	t.Parallel()

	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method: got %s want %s", r.Method, http.MethodPost)
		}
		if r.URL.Path != "/api/v0/add" {
			t.Fatalf("path: got %s want /api/v0/add", r.URL.Path)
		}
		if got := r.URL.Query().Get("pin"); got != "true" {
			t.Fatalf("query pin: got %q want %q", got, "true")
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		gotBody = string(b)
		_ = json.NewEncoder(w).Encode(map[string]any{"Hash": "bafybeigdyrzt"})
	}))
	defer srv.Close()

	pinner, err := NewHTTPIPFSPinner(HTTPIPFSConfig{APIURL: srv.URL})
	if err != nil {
		t.Fatalf("NewHTTPIPFSPinner: %v", err)
	}

	cid, err := pinner.PinJSON(context.Background(), []byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("PinJSON: %v", err)
	}
	if cid != "bafybeigdyrzt" {
		t.Fatalf("cid: got %q want %q", cid, "bafybeigdyrzt")
	}
	if !strings.Contains(gotBody, `{"hello":"world"}`) {
		t.Fatalf("multipart body does not contain payload")
	}
}

func TestHTTPIPFSPinner_RejectsErrorResponse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()

	pinner, err := NewHTTPIPFSPinner(HTTPIPFSConfig{APIURL: srv.URL})
	if err != nil {
		t.Fatalf("NewHTTPIPFSPinner: %v", err)
	}

	_, err = pinner.PinJSON(context.Background(), []byte(`{"hello":"world"}`))
	if err == nil {
		t.Fatalf("expected error")
	}
}
