package healthz

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

type response struct {
	Status  string `json:"status"`
	Uptime  string `json:"uptime"`
	Service string `json:"service"`
}

// ListenAndServe starts a minimal HTTP server with a /healthz endpoint.
// It blocks until ctx is cancelled, then shuts down gracefully.
// If addr is empty or "0", the server is not started and nil is returned immediately.
func ListenAndServe(ctx context.Context, addr string, serviceName string) error {
	if addr == "" || addr == "0" {
		<-ctx.Done()
		return nil
	}

	startTime := time.Now()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		uptime := time.Since(startTime).Truncate(time.Second).String()
		_ = json.NewEncoder(w).Encode(response{
			Status:  "ok",
			Uptime:  uptime,
			Service: serviceName,
		})
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("healthz: %w", err)
		}
		return nil
	}
}

// Handler returns an http.HandlerFunc for /healthz that can be added to an existing mux.
func Handler(serviceName string, startTime time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		uptime := time.Since(startTime).Truncate(time.Second).String()
		_ = json.NewEncoder(w).Encode(response{
			Status:  "ok",
			Uptime:  uptime,
			Service: serviceName,
		})
	}
}

// ListenAddr constructs a listen address from a port number.
// Returns empty string if port is 0.
func ListenAddr(port int) string {
	if port == 0 {
		return ""
	}
	return net.JoinHostPort("", fmt.Sprintf("%d", port))
}
