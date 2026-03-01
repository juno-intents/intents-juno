package backoffice

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"sync"
)

//go:embed templates/* static/*
var embeddedFS embed.FS

var (
	parsedTemplates *template.Template
	parseOnce       sync.Once
	parseErr        error
)

// Templates returns the parsed HTML templates. Templates are parsed once and
// cached for the lifetime of the process.
func Templates() (*template.Template, error) {
	parseOnce.Do(func() {
		parsedTemplates, parseErr = template.ParseFS(embeddedFS, "templates/*.html")
	})
	return parsedTemplates, parseErr
}

// RenderDashboard writes the main dashboard HTML page to w. It renders the
// "layout.html" template.
func RenderDashboard(w http.ResponseWriter) {
	tmpl, err := Templates()
	if err != nil {
		http.Error(w, "template parse error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout.html", nil); err != nil {
		http.Error(w, "template render error: "+err.Error(), http.StatusInternalServerError)
	}
}

// StaticHandler returns an http.Handler that serves the embedded static files
// (CSS, JS) from the "static" subdirectory. Callers should strip the "/static/"
// prefix before delegating to this handler.
func StaticHandler() http.Handler {
	staticFS, err := fs.Sub(embeddedFS, "static")
	if err != nil {
		// This would only happen if the embed directive is wrong, which is a
		// build-time issue. Panic is acceptable here.
		panic("backoffice: failed to create static sub-filesystem: " + err.Error())
	}
	return http.FileServer(http.FS(staticFS))
}
