package alerts

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

// envelope is the standard API response wrapper.
type envelope struct {
	Version string      `json:"version"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// RegisterRoutes registers alert HTTP endpoints on the given ServeMux.
func RegisterRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("GET /api/alerts/active", handleListActive(store))
	mux.HandleFunc("GET /api/alerts/history", handleListHistory(store))
	mux.HandleFunc("GET /api/alerts/count", handleCountActive(store))
	mux.HandleFunc("POST /api/alerts/{id}/acknowledge", handleAcknowledge(store))
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("alerts: failed to encode response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, envelope{Version: "v1", Error: msg})
}

func handleListActive(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		alerts, err := store.ListActive(r.Context())
		if err != nil {
			slog.Error("alerts: list active failed", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to list active alerts")
			return
		}
		if alerts == nil {
			alerts = []Alert{}
		}
		writeJSON(w, http.StatusOK, envelope{Version: "v1", Data: alerts})
	}
}

func handleListHistory(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if limit <= 0 {
			limit = 50
		}
		alerts, err := store.ListHistory(r.Context(), limit, offset)
		if err != nil {
			slog.Error("alerts: list history failed", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to list alert history")
			return
		}
		if alerts == nil {
			alerts = []Alert{}
		}
		writeJSON(w, http.StatusOK, envelope{Version: "v1", Data: alerts})
	}
}

func handleCountActive(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		count, err := store.CountActive(r.Context())
		if err != nil {
			slog.Error("alerts: count active failed", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to count active alerts")
			return
		}
		writeJSON(w, http.StatusOK, envelope{Version: "v1", Data: map[string]int{"count": count}})
	}
}

// ackRequest is the request body for acknowledging an alert.
type ackRequest struct {
	By string `json:"by"`
}

func handleAcknowledge(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract {id} from the URL path.
		idStr := r.PathValue("id")
		if idStr == "" {
			// Fallback: parse from URL path for older Go versions.
			parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
			if len(parts) >= 4 {
				idStr = parts[len(parts)-2] // /api/alerts/{id}/acknowledge
			}
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid alert id")
			return
		}

		var req ackRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.By == "" {
			writeError(w, http.StatusBadRequest, "\"by\" field is required")
			return
		}

		if err := store.AcknowledgeAlert(r.Context(), id, req.By); err != nil {
			slog.Error("alerts: acknowledge failed", "id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to acknowledge alert")
			return
		}
		writeJSON(w, http.StatusOK, envelope{Version: "v1", Data: "ok"})
	}
}
