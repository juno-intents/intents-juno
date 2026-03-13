package healthz

import (
	"context"
	"encoding/json"
	"errors"
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

func TestRegisterAddsLiveReadyAndLegacyHealthPaths(t *testing.T) {
	t.Parallel()

	startTime := time.Now().Add(-time.Minute)
	mux := http.NewServeMux()
	Register(mux, "test-service", startTime)

	for _, path := range []string{"/livez", "/readyz", "/healthz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("%s status: got %d want %d", path, w.Code, http.StatusOK)
		}
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

func TestRegister_ReadyzReflectsDependencyHealth(t *testing.T) {
	t.Parallel()

	startTime := time.Now().Add(-time.Minute)
	mux := http.NewServeMux()
	Register(mux, "test-service", startTime, WithReadinessCheck(func(context.Context) error {
		return errors.New("db unavailable")
	}))

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}

	var resp struct {
		Status  string `json:"status"`
		Service string `json:"service"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "not_ready" {
		t.Fatalf("expected status=not_ready, got %q", resp.Status)
	}
	if resp.Service != "test-service" {
		t.Fatalf("expected service=test-service, got %q", resp.Service)
	}
	if resp.Error != "db unavailable" {
		t.Fatalf("expected readiness error, got %q", resp.Error)
	}
}

func TestRegister_LivezAndHealthzShareLivenessHandler(t *testing.T) {
	t.Parallel()

	startTime := time.Now().Add(-time.Minute)
	mux := http.NewServeMux()
	Register(mux, "test-service", startTime)

	for _, path := range []string{"/livez", "/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("%s expected 200, got %d", path, w.Code)
		}
	}
}

func TestCombineReadinessChecks_StopsAtFirstFailure(t *testing.T) {
	t.Parallel()

	calls := 0
	check := CombineReadinessChecks(
		func(context.Context) error {
			calls++
			return nil
		},
		func(context.Context) error {
			calls++
			return errors.New("db unavailable")
		},
		func(context.Context) error {
			calls++
			return nil
		},
	)
	if check == nil {
		t.Fatalf("expected combined readiness check")
	}

	err := check(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "db unavailable" {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected to stop after first failure, got %d calls", calls)
	}
}
