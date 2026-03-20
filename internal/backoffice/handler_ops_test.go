package backoffice

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeIPFS_UsesBearerTokenWhenConfigured(t *testing.T) {
	t.Parallel()

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"Version":"0.1.0"}`)
	}))
	defer srv.Close()

	result := probeIPFS(context.Background(), srv.Client(), srv.URL, "secret-token")
	if healthy, ok := result["healthy"].(bool); !ok || !healthy {
		t.Fatalf("healthy = %#v, want true", result["healthy"])
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("Authorization header = %q, want %q", gotAuth, "Bearer secret-token")
	}
}

func TestDepositStateIsStuckIncludesSubmitted(t *testing.T) {
	t.Parallel()

	if !depositStateIsStuck(5) {
		t.Fatalf("expected submitted deposits to be considered stuck when stale")
	}
	if depositStateIsStuck(6) {
		t.Fatalf("expected finalized deposits to be excluded from stuck view")
	}
	if depositStateIsStuck(7) {
		t.Fatalf("expected rejected deposits to be excluded from stuck view")
	}
}
