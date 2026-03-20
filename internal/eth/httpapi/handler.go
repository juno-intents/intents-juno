package httpapi

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/juno-intents/intents-juno/internal/eth"
)

type Sender interface {
	SendAndWaitMined(ctx context.Context, req eth.TxRequest) (eth.SendResult, error)
}

type Config struct {
	// AuthToken enables bearer-token auth on every request when set.
	AuthToken string

	// AuthPrincipal is the rate-limit principal used for authenticated requests.
	// Empty defaults to "authenticated" whenever bearer auth succeeds.
	AuthPrincipal string

	// ReadinessCheck is evaluated for /readyz. Nil means always ready.
	ReadinessCheck func(context.Context) error

	// AllowedContracts limits /v1/send targets. Empty means /v1/send fails closed.
	AllowedContracts []common.Address

	// AllowedSelectors limits /v1/send calldata selectors. Empty means /v1/send fails closed.
	AllowedSelectors [][]byte

	// MaxBodyBytes limits request sizes to prevent memory DoS. Defaults to 1 MiB.
	MaxBodyBytes int64

	// MaxWaitSeconds bounds per-request execution time (server-side). Defaults to 300s.
	MaxWaitSeconds int

	// IdempotencyTTL bounds how long completed send outcomes stay replayable.
	IdempotencyTTL time.Duration

	// IdempotencyMaxKeys bounds in-memory idempotency state.
	IdempotencyMaxKeys int

	// RateLimitPerSecond is the per-client token-bucket refill rate.
	RateLimitPerSecond float64

	// RateLimitBurst is the per-client token-bucket burst size.
	RateLimitBurst int

	// RateLimitMaxTrackedClients bounds in-memory client limiter state.
	RateLimitMaxTrackedClients int

	// Log is used to log internal errors. If nil, errors are logged to slog.Default().
	Log *slog.Logger

	Now func() time.Time
}

func NewHandler(sender Sender, cfg Config) http.Handler {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.MaxWaitSeconds <= 0 {
		cfg.MaxWaitSeconds = 300
	}
	if cfg.IdempotencyTTL <= 0 {
		cfg.IdempotencyTTL = 15 * time.Minute
	}
	if cfg.IdempotencyMaxKeys <= 0 {
		cfg.IdempotencyMaxKeys = 10_000
	}
	if cfg.RateLimitPerSecond <= 0 {
		cfg.RateLimitPerSecond = 20
	}
	if cfg.RateLimitBurst <= 0 {
		cfg.RateLimitBurst = 40
	}
	if cfg.RateLimitMaxTrackedClients <= 0 {
		cfg.RateLimitMaxTrackedClients = 10_000
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	mux := http.NewServeMux()
	allowedContracts := make(map[common.Address]struct{}, len(cfg.AllowedContracts))
	for _, addr := range cfg.AllowedContracts {
		allowedContracts[addr] = struct{}{}
	}
	allowedSelectors := make(map[[4]byte]struct{}, len(cfg.AllowedSelectors))
	for _, selector := range cfg.AllowedSelectors {
		if len(selector) != 4 {
			continue
		}
		var key [4]byte
		copy(key[:], selector)
		allowedSelectors[key] = struct{}{}
	}
	limiter := newClientRateLimiter(cfg.RateLimitPerSecond, cfg.RateLimitBurst, cfg.RateLimitMaxTrackedClients)
	idempotency := newIdempotencyCache(cfg.IdempotencyTTL, cfg.IdempotencyMaxKeys)

	startTime := cfg.Now()
	handleHealth := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		uptime := cfg.Now().Sub(startTime).Truncate(time.Second).String()
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"uptime":  uptime,
			"service": "base-relayer",
		})
	}
	handleReady := func(w http.ResponseWriter, r *http.Request) {
		if cfg.ReadinessCheck != nil {
			if err := cfg.ReadinessCheck(r.Context()); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				uptime := cfg.Now().Sub(startTime).Truncate(time.Second).String()
				_ = json.NewEncoder(w).Encode(map[string]string{
					"status":  "not_ready",
					"uptime":  uptime,
					"service": "base-relayer",
					"error":   err.Error(),
				})
				return
			}
		}
		handleHealth(w, r)
	}
	mux.HandleFunc("GET /livez", handleHealth)
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /readyz", handleReady)

	mux.HandleFunc("POST /v1/send", func(w http.ResponseWriter, r *http.Request) {
		bearerToken, authorized := parseBearer(r.Header.Get("Authorization"), cfg.AuthToken)
		if cfg.AuthToken != "" && !authorized {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}

		authPrincipal := strings.TrimSpace(cfg.AuthPrincipal)
		if bearerToken != "" && authPrincipal == "" {
			authPrincipal = "authenticated"
		}
		if !limiter.Allow(clientKey(r, authPrincipal), cfg.Now().UTC()) {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate_limited"})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "request_too_large"})
				return
			}
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
			return
		}

		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.DisallowUnknownFields()

		var req SendRequest
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
			return
		}
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
			return
		}

		if !common.IsHexAddress(req.To) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_to"})
			return
		}
		to := common.HexToAddress(req.To)

		var data []byte
		if req.Data != "" {
			b, err := hexutil.Decode(req.Data)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_data"})
				return
			}
			data = b
		}

		value := big.NewInt(0)
		if req.ValueWei != "" {
			v, ok := new(big.Int).SetString(req.ValueWei, 10)
			if !ok || v.Sign() < 0 {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_value_wei"})
				return
			}
			value = v
		}
		if value.Sign() != 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "nonzero_value_not_allowed"})
			return
		}

		if len(allowedContracts) == 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "contract_allowlist_not_configured"})
			return
		}
		if _, ok := allowedContracts[to]; !ok {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "contract_not_allowed"})
			return
		}
		if len(allowedSelectors) == 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "selector_allowlist_not_configured"})
			return
		}
		if len(data) < 4 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing_selector"})
			return
		}
		var selector [4]byte
		copy(selector[:], data[:4])
		if _, ok := allowedSelectors[selector]; !ok {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "selector_not_allowed"})
			return
		}

		timeout := time.Duration(cfg.MaxWaitSeconds) * time.Second
		if req.TimeoutSeconds > 0 {
			requestTimeout := time.Duration(req.TimeoutSeconds) * time.Second
			if requestTimeout < timeout {
				timeout = requestTimeout
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		var reservation *idempotencyReservation
		if key := strings.TrimSpace(r.Header.Get("Idempotency-Key")); key != "" {
			status, body, res, err := idempotency.Start(ctx, key, canonicalRequestHash(to, data, value, req.GasLimit, req.TimeoutSeconds), cfg.Now().UTC())
			if err != nil {
				switch {
				case errors.Is(err, errIdempotencyKeyConflict):
					writeJSON(w, http.StatusConflict, map[string]any{"error": "idempotency_key_reused"})
				case errors.Is(err, context.Canceled):
					writeJSON(w, http.StatusRequestTimeout, map[string]any{"error": "canceled"})
				case errors.Is(err, context.DeadlineExceeded):
					writeJSON(w, http.StatusGatewayTimeout, map[string]any{"error": "timeout"})
				default:
					cfg.Log.Error("idempotency reservation failed", "err", err)
					writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal"})
				}
				return
			}
			if res == nil {
				writeJSONBytes(w, status, body)
				return
			}
			reservation = res
			defer func() {
				if reservation != nil {
					reservation.Complete(http.StatusInternalServerError, mustJSON(map[string]any{"error": "internal"}), cfg.Now().UTC())
				}
			}()
		}

		res, err := sender.SendAndWaitMined(ctx, eth.TxRequest{
			To:       to,
			Data:     data,
			Value:    value,
			GasLimit: req.GasLimit,
		})
		if err != nil {
			switch {
			case errors.Is(err, context.DeadlineExceeded):
				completeReservation(reservation, http.StatusGatewayTimeout, mustJSON(map[string]any{"error": "timeout"}), cfg.Now().UTC())
				reservation = nil
				writeJSON(w, http.StatusGatewayTimeout, map[string]any{"error": "timeout"})
			case errors.Is(err, context.Canceled):
				completeReservation(reservation, http.StatusRequestTimeout, mustJSON(map[string]any{"error": "canceled"}), cfg.Now().UTC())
				reservation = nil
				writeJSON(w, http.StatusRequestTimeout, map[string]any{"error": "canceled"})
			case errors.Is(err, eth.ErrFeeCapReached):
				completeReservation(reservation, http.StatusConflict, mustJSON(map[string]any{"error": "fee_cap_reached"}), cfg.Now().UTC())
				reservation = nil
				writeJSON(w, http.StatusConflict, map[string]any{"error": "fee_cap_reached"})
			default:
				cfg.Log.Error("send transaction failed", "to", req.To, "err", err)
				completeReservation(reservation, http.StatusInternalServerError, mustJSON(map[string]any{"error": "internal", "detail": err.Error()}), cfg.Now().UTC())
				reservation = nil
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal", "detail": err.Error()})
			}
			return
		}

		out := SendResponse{
			From:         res.From.Hex(),
			Nonce:        res.Nonce,
			TxHash:       res.TxHash.Hex(),
			Replacements: res.Replacements,
		}
		if res.Receipt != nil {
			out.Receipt = &ReceiptResponse{
				Status: res.Receipt.Status,
			}
			if res.Receipt.BlockNumber != nil {
				out.Receipt.BlockNumber = res.Receipt.BlockNumber.String()
			}
			if res.Receipt.GasUsed != 0 {
				out.Receipt.GasUsed = res.Receipt.GasUsed
			}
			if res.RevertReason != "" {
				out.Receipt.RevertReason = res.RevertReason
			}
			if len(res.RevertData) > 0 {
				out.Receipt.RevertData = hexutil.Encode(res.RevertData)
			}
		}

		body := mustJSON(out)
		completeReservation(reservation, http.StatusOK, body, cfg.Now().UTC())
		reservation = nil
		writeJSONBytes(w, http.StatusOK, body)
	})

	return mux
}

func completeReservation(reservation *idempotencyReservation, status int, body []byte, now time.Time) {
	if reservation == nil {
		return
	}
	reservation.Complete(status, body, now)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	writeJSONBytes(w, status, mustJSON(v))
}

func writeJSONBytes(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func mustJSON(v any) []byte {
	body, err := json.Marshal(v)
	if err != nil {
		return []byte("{\"error\":\"internal\"}\n")
	}
	return append(body, '\n')
}

func parseBearer(header string, wantToken string) (string, bool) {
	// Conservative parsing: exact "Bearer <token>" with single space.
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	got := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if wantToken == "" {
		return got, true
	}
	return got, subtle.ConstantTimeCompare([]byte(got), []byte(wantToken)) == 1
}
