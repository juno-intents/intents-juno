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
	Error   string `json:"error,omitempty"`
}

type readinessCheck func(context.Context) error

type options struct {
	readiness readinessCheck
}

// Option mutates health probe behavior.
type Option func(*options)

// WithReadinessCheck configures a dependency probe for /readyz.
func WithReadinessCheck(check func(context.Context) error) Option {
	return func(opts *options) {
		opts.readiness = check
	}
}

func buildOptions(opts []Option) options {
	var out options
	for _, opt := range opts {
		if opt != nil {
			opt(&out)
		}
	}
	return out
}

func CombineReadinessChecks(checks ...func(context.Context) error) func(context.Context) error {
	filtered := make([]func(context.Context) error, 0, len(checks))
	for _, check := range checks {
		if check != nil {
			filtered = append(filtered, check)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return func(ctx context.Context) error {
		for _, check := range filtered {
			if err := check(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}

// Register adds the standard liveness and readiness probes to mux.
// /healthz is retained as a compatibility alias for /livez.
func Register(mux *http.ServeMux, serviceName string, startTime time.Time, opts ...Option) {
	if mux == nil {
		panic("healthz: nil mux")
	}
	cfg := buildOptions(opts)
	liveHandler := Handler(serviceName, startTime)
	readyHandler := ReadyHandler(serviceName, startTime, cfg.readiness)

	mux.HandleFunc("GET /livez", liveHandler)
	mux.HandleFunc("GET /healthz", liveHandler)
	mux.HandleFunc("GET /readyz", readyHandler)
}

// ListenAndServe starts a minimal HTTP server with /livez and /readyz endpoints.
// /healthz is retained as a compatibility alias for /livez.
// It blocks until ctx is cancelled, then shuts down gracefully.
// If addr is empty or "0", the server is not started and nil is returned immediately.
func ListenAndServe(ctx context.Context, addr string, serviceName string, opts ...Option) error {
	if addr == "" || addr == "0" {
		<-ctx.Done()
		return nil
	}

	startTime := time.Now()

	mux := http.NewServeMux()
	Register(mux, serviceName, startTime, opts...)

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

// Handler returns an http.HandlerFunc for live and ready probes.
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

// ReadyHandler returns an http.HandlerFunc for /readyz.
func ReadyHandler(serviceName string, startTime time.Time, check func(context.Context) error) http.HandlerFunc {
	liveHandler := Handler(serviceName, startTime)
	return func(w http.ResponseWriter, r *http.Request) {
		if check == nil {
			liveHandler(w, r)
			return
		}
		if err := check(r.Context()); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			uptime := time.Since(startTime).Truncate(time.Second).String()
			_ = json.NewEncoder(w).Encode(response{
				Status:  "not_ready",
				Uptime:  uptime,
				Service: serviceName,
				Error:   err.Error(),
			})
			return
		}
		liveHandler(w, r)
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
