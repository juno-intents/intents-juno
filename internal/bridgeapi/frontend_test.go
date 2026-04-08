//go:build !nofrontend

package bridgeapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFrontendHandler_ServesEmbeddedWhitepaper(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/whitepaper.pdf", nil)
	rec := httptest.NewRecorder()

	FrontendHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/pdf") {
		t.Fatalf("content-type: got %q want application/pdf", got)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("expected non-empty whitepaper body")
	}
}
