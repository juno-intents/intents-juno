package tsshost

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/juno-intents/intents-juno/internal/tss"
)

type Signer interface {
	// Sign returns a signed transaction for the provided txPlan, binding it to sessionID.
	//
	// Implementations MUST be safe to call multiple times (at-least-once request semantics).
	Sign(ctx context.Context, sessionID [32]byte, txPlan []byte) ([]byte, error)
}

type Config struct {
	// MaxBodyBytes limits HTTP request size to prevent memory DoS.
	// Defaults to 1 MiB.
	MaxBodyBytes int64

	// MaxTxPlanBytes bounds the decoded txPlan bytes in the request.
	// Defaults to 1 MiB.
	MaxTxPlanBytes int

	// MaxSessions bounds the number of in-memory sessions tracked for idempotency.
	// Defaults to 1024.
	MaxSessions int

	// SessionTTL evicts completed sessions after the configured age.
	// Defaults to 15 minutes.
	SessionTTL time.Duration

	// ReadinessCheck is evaluated for /readyz before the built-in session-capacity
	// check. Nil means only session capacity gates readiness.
	ReadinessCheck func(context.Context) error

	// Log emits audit records for sign requests. Defaults to a discard logger.
	Log *slog.Logger

	Now func() time.Time
}

type handler struct {
	cfg    Config
	signer Signer

	mu       sync.Mutex
	sessions map[[32]byte]*session
}

type session struct {
	txPlanHash [32]byte

	signing bool
	done    chan struct{}

	signedTx []byte
	lastErr  error
	lastSeen time.Time
}

func NewHandler(signer Signer, cfg Config) http.Handler {
	if signer == nil {
		panic("tsshost: nil signer")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.MaxTxPlanBytes <= 0 {
		cfg.MaxTxPlanBytes = 1 << 20
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 1024
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 15 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	h := &handler{
		cfg:      cfg,
		signer:   signer,
		sessions: make(map[[32]byte]*session),
	}

	mux := http.NewServeMux()

	handleHealth := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}
	handleReady := func(w http.ResponseWriter, r *http.Request) {
		if err := h.readinessCheck(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "not_ready", "detail": err.Error()})
			return
		}
		handleHealth(w, r)
	}
	mux.HandleFunc("GET /livez", handleHealth)
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /readyz", handleReady)

	mux.HandleFunc("POST /v1/sign", h.handleSign)
	return mux
}

func (h *handler) handleSign(w http.ResponseWriter, r *http.Request) {
	startedAt := h.cfg.Now().UTC()
	sessionIDForLog := ""

	r.Body = http.MaxBytesReader(w, r.Body, h.cfg.MaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req tss.SignRequest
	if err := dec.Decode(&req); err != nil {
		h.audit("", "invalid_json", startedAt)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}
	// Reject trailing garbage.
	if dec.More() {
		h.audit("", "invalid_json", startedAt)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}

	if req.Version != tss.SignRequestVersion {
		h.audit("", "invalid_version", startedAt)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_version"})
		return
	}
	sid, err := tss.ParseSessionID(req.SessionID)
	if err != nil {
		h.audit(req.SessionID, "invalid_session_id", startedAt)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_session_id"})
		return
	}
	sessionIDForLog = tss.FormatSessionID(sid)
	if len(req.TxPlan) == 0 {
		h.audit(sessionIDForLog, "missing_tx_plan", startedAt)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing_tx_plan"})
		return
	}
	if len(req.TxPlan) > h.cfg.MaxTxPlanBytes {
		h.audit(sessionIDForLog, "tx_plan_too_large", startedAt)
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "tx_plan_too_large"})
		return
	}

	txPlanHash := sha256.Sum256(req.TxPlan)

	signedTx, outcome, err := h.signOnce(r.Context(), sid, txPlanHash, req.TxPlan)
	if err != nil {
		switch {
		case errors.Is(err, errConflict):
			h.audit(sessionIDForLog, "session_conflict", startedAt)
		case errors.Is(err, errTooManySessions):
			h.audit(sessionIDForLog, "too_many_sessions", startedAt)
		case errors.Is(err, context.Canceled):
			h.audit(sessionIDForLog, "canceled", startedAt)
		case errors.Is(err, context.DeadlineExceeded):
			h.audit(sessionIDForLog, "timeout", startedAt)
		default:
			h.audit(sessionIDForLog, "internal_error", startedAt)
		}
		if errors.Is(err, errConflict) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "session_conflict"})
			return
		}
		if errors.Is(err, context.Canceled) {
			writeJSON(w, http.StatusRequestTimeout, map[string]any{"error": "canceled"})
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			writeJSON(w, http.StatusGatewayTimeout, map[string]any{"error": "timeout"})
			return
		}
		if errors.Is(err, errTooManySessions) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "too_many_sessions"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal"})
		return
	}
	h.audit(sessionIDForLog, outcome, startedAt)

	resp := tss.SignResponse{
		Version:   tss.SignResponseVersion,
		SessionID: tss.FormatSessionID(sid),
		SignedTx:  signedTx,
	}
	writeJSON(w, http.StatusOK, resp)
}

var (
	errConflict        = errors.New("tsshost: session conflict")
	errTooManySessions = errors.New("tsshost: too many sessions")
)

func (h *handler) signOnce(ctx context.Context, sid [32]byte, txPlanHash [32]byte, txPlan []byte) ([]byte, string, error) {
	for {
		h.mu.Lock()
		now := h.cfg.Now().UTC()
		h.evictExpiredSessions(now)
		sess, ok := h.sessions[sid]
		if ok {
			sess.lastSeen = now
			if sess.txPlanHash != txPlanHash {
				h.mu.Unlock()
				return nil, "", errConflict
			}
			if len(sess.signedTx) > 0 {
				out := append([]byte(nil), sess.signedTx...)
				h.mu.Unlock()
				return out, "cached_session", nil
			}
			if sess.signing {
				done := sess.done
				h.mu.Unlock()
				select {
				case <-done:
					continue
				case <-ctx.Done():
					return nil, "", ctx.Err()
				}
			}

			// Retry (or first attempt) for an existing session with matching txPlanHash.
			sess.signing = true
			sess.done = make(chan struct{})
			h.mu.Unlock()

			signedTx, err := h.signer.Sign(ctx, sid, txPlan)

			h.mu.Lock()
			sess.signing = false
			sess.lastErr = err
			sess.lastSeen = h.cfg.Now().UTC()
			if err == nil {
				sess.signedTx = append([]byte(nil), signedTx...)
			}
			close(sess.done)
			h.mu.Unlock()

			if err != nil {
				return nil, "", err
			}
			return append([]byte(nil), signedTx...), "retried_session", nil
		}

		if len(h.sessions) >= h.cfg.MaxSessions {
			h.mu.Unlock()
			return nil, "", errTooManySessions
		}

		sess = &session{
			txPlanHash: txPlanHash,
			signing:    true,
			done:       make(chan struct{}),
			lastSeen:   now,
		}
		h.sessions[sid] = sess
		h.mu.Unlock()

		signedTx, err := h.signer.Sign(ctx, sid, txPlan)

		h.mu.Lock()
		sess.signing = false
		sess.lastErr = err
		sess.lastSeen = h.cfg.Now().UTC()
		if err == nil {
			sess.signedTx = append([]byte(nil), signedTx...)
		}
		close(sess.done)
		h.mu.Unlock()

		if err != nil {
			return nil, "", err
		}
		return append([]byte(nil), signedTx...), "new_session", nil
	}
}

func (h *handler) evictExpiredSessions(now time.Time) {
	if h.cfg.SessionTTL <= 0 {
		return
	}
	for sid, sess := range h.sessions {
		if sess.signing {
			continue
		}
		if now.Sub(sess.lastSeen) <= h.cfg.SessionTTL {
			continue
		}
		delete(h.sessions, sid)
	}
}

func (h *handler) readinessCheck(ctx context.Context) error {
	if h.cfg.ReadinessCheck != nil {
		if err := h.cfg.ReadinessCheck(ctx); err != nil {
			return err
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	now := h.cfg.Now().UTC()
	h.evictExpiredSessions(now)
	if len(h.sessions) >= h.cfg.MaxSessions {
		return fmt.Errorf("tsshost: session capacity exhausted")
	}
	return nil
}

func (h *handler) audit(sessionID string, result string, startedAt time.Time) {
	if h.cfg.Log == nil {
		return
	}
	duration := h.cfg.Now().UTC().Sub(startedAt)
	if duration < 0 {
		duration = 0
	}
	h.cfg.Log.Info("tsshost sign request",
		"session_id", sessionID,
		"result", result,
		"duration_ms", duration.Milliseconds(),
	)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
