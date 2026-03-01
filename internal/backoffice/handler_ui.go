package backoffice

import (
	"net/http"
)

// RegisterUIRoutes registers the dashboard UI routes on the given mux:
//   - GET /        — render the main dashboard HTML page
//   - GET /static/ — serve embedded CSS and JS assets
func RegisterUIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", handleDashboard)
	mux.Handle("GET /static/", http.StripPrefix("/static/", StaticHandler()))
}

func handleDashboard(w http.ResponseWriter, _ *http.Request) {
	RenderDashboard(w)
}
