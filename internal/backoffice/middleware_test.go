package backoffice

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
