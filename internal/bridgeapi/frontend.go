//go:build !nofrontend

package bridgeapi

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed frontend_dist/*
var frontendFS embed.FS

// FrontendHandler returns an http.Handler that serves the embedded frontend.
// Non-existent paths fall back to index.html for client-side routing.
func FrontendHandler() http.Handler {
	sub, err := fs.Sub(frontendFS, "frontend_dist")
	if err != nil {
		// Should never happen with valid embed directive.
		return http.NotFoundHandler()
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to serve the exact file first.
		f, err := sub.Open(r.URL.Path[1:]) // strip leading /
		if err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		// Fallback to index.html for SPA routing.
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}
