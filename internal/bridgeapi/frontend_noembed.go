//go:build nofrontend

package bridgeapi

import "net/http"

// FrontendHandler returns a handler that responds with 404 when the frontend
// is not embedded (built with -tags nofrontend).
func FrontendHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "frontend not available", http.StatusNotFound)
	})
}
