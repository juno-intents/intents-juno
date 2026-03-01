package healthz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandler(t *testing.T) {
	t.Parallel()

	startTime := time.Now().Add(-90 * time.Minute)
	h := Handler("test-service", startTime)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}

	var resp struct {
		Status  string `json:"status"`
		Uptime  string `json:"uptime"`
		Service string `json:"service"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("expected status=ok, got %q", resp.Status)
	}
	if resp.Service != "test-service" {
		t.Fatalf("expected service=test-service, got %q", resp.Service)
	}
	if resp.Uptime == "" {
		t.Fatal("expected non-empty uptime")
	}
}

func TestListenAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		port int
		want string
	}{
		{0, ""},
		{8080, ":8080"},
		{3000, ":3000"},
	}

	for _, tt := range tests {
		got := ListenAddr(tt.port)
		if got != tt.want {
			t.Errorf("ListenAddr(%d) = %q, want %q", tt.port, got, tt.want)
		}
	}
}

func TestListenAndServe_DisabledPort(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel

	err := ListenAndServe(ctx, "", "test")
	if err != nil {
		t.Fatalf("expected nil error for disabled port, got %v", err)
	}
}
