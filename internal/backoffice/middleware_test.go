package backoffice

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseDLQFilter_LimitCap(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("GET", "/dlq/proofs?limit=9999", nil)
	filter := parseDLQFilter(req)
	if filter.Limit != 1000 {
		t.Fatalf("limit should be capped at 1000: got %d", filter.Limit)
	}

	req2 := httptest.NewRequest("GET", "/dlq/proofs?limit=500", nil)
	filter2 := parseDLQFilter(req2)
	if filter2.Limit != 500 {
		t.Fatalf("limit within range should be preserved: got %d", filter2.Limit)
	}
}

func TestExtractClientIP_IgnoresProxyHeaders(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.7:4321"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("X-Real-IP", "10.0.0.2")

	ip := extractClientIP(req)
	if ip != "198.51.100.7" {
		t.Fatalf("extractClientIP should ignore proxy headers: got %q want 198.51.100.7", ip)
	}
}

func TestAuthMiddleware_ConstantTimeComparison(t *testing.T) {
	t.Parallel()

	// Verify that a slightly different token is rejected (basic sanity for
	// constant-time path; timing analysis is out of scope for unit tests).
	s := &Server{cfg: ServerConfig{AuthSecret: "correct-secret"}}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.authMiddleware(inner)

	req := httptest.NewRequest("GET", "/api/funds", nil)
	req.Header.Set("Authorization", "Bearer correct-secre")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("prefix of secret should not authenticate: got %d", rec.Code)
	}
}

func TestAuthMiddleware_UIPathsExempt(t *testing.T) {
	s := &Server{
		cfg: ServerConfig{AuthSecret: "test-secret"},
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	handler := s.authMiddleware(inner)

	tests := []struct {
		name       string
		path       string
		authHeader string
		wantCode   int
	}{
		{
			name:     "livez exempt",
			path:     "/livez",
			wantCode: http.StatusOK,
		},
		{
			name:     "readyz exempt",
			path:     "/readyz",
			wantCode: http.StatusOK,
		},
		{
			name:     "healthz exempt",
			path:     "/healthz",
			wantCode: http.StatusOK,
		},
		{
			name:     "root path exempt",
			path:     "/",
			wantCode: http.StatusOK,
		},
		{
			name:     "static assets exempt",
			path:     "/static/style.css",
			wantCode: http.StatusOK,
		},
		{
			name:     "static js exempt",
			path:     "/static/app.js",
			wantCode: http.StatusOK,
		},
		{
			name:     "api without auth rejected",
			path:     "/api/funds",
			wantCode: http.StatusUnauthorized,
		},
		{
			name:       "api with valid auth allowed",
			path:       "/api/funds",
			authHeader: "Bearer test-secret",
			wantCode:   http.StatusOK,
		},
		{
			name:       "api with wrong token rejected",
			path:       "/api/funds",
			authHeader: "Bearer wrong",
			wantCode:   http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantCode {
				t.Errorf("path=%s: got status %d, want %d", tt.path, rec.Code, tt.wantCode)
			}
		})
	}
}
