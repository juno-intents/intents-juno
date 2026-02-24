package bridgeapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/deposit"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/withdraw"
	"github.com/juno-intents/intents-juno/internal/withdrawrequest"
)

var ErrInvalidConfig = errors.New("bridgeapi: invalid config")

type Config struct {
	BaseChainID         uint32
	BridgeAddress       common.Address
	OWalletUA           string
	RefundWindowSeconds uint64
	NonceFn             func() (uint64, error)
	ActionService       ActionService

	RateLimitPerIPPerSecond float64
	RateLimitBurst          int
	RateLimitMaxTrackedIPs  int

	MemoCacheTTL        time.Duration
	MemoCacheMaxEntries int

	Now func() time.Time
}

type DepositReader interface {
	Get(ctx context.Context, depositID [32]byte) (deposit.Job, error)
}

type WithdrawalStatus struct {
	Withdrawal withdraw.Withdrawal
	BatchID    *[32]byte
	BatchState withdraw.BatchState
	JunoTxID   string
	BaseTxHash string
}

type WithdrawalReader interface {
	Get(ctx context.Context, withdrawalID [32]byte) (WithdrawalStatus, error)
}

func NewHandler(cfg Config, deposits DepositReader, withdrawals WithdrawalReader) (http.Handler, error) {
	if cfg.BaseChainID == 0 {
		return nil, fmt.Errorf("%w: missing base chain id", ErrInvalidConfig)
	}
	if cfg.BridgeAddress == (common.Address{}) {
		return nil, fmt.Errorf("%w: missing bridge address", ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.OWalletUA) == "" {
		return nil, fmt.Errorf("%w: missing owallet ua", ErrInvalidConfig)
	}
	if deposits == nil || withdrawals == nil {
		return nil, fmt.Errorf("%w: nil readers", ErrInvalidConfig)
	}
	if cfg.NonceFn == nil {
		cfg.NonceFn = randomNonce
	}
	if cfg.RateLimitPerIPPerSecond <= 0 {
		cfg.RateLimitPerIPPerSecond = 20
	}
	if cfg.RateLimitBurst <= 0 {
		cfg.RateLimitBurst = 40
	}
	if cfg.RateLimitMaxTrackedIPs <= 0 {
		cfg.RateLimitMaxTrackedIPs = 10_000
	}
	if cfg.MemoCacheTTL <= 0 {
		cfg.MemoCacheTTL = 30 * time.Second
	}
	if cfg.MemoCacheMaxEntries <= 0 {
		cfg.MemoCacheMaxEntries = 10_000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	h := &handler{
		cfg:         cfg,
		deposits:    deposits,
		withdrawals: withdrawals,
		actions:     cfg.ActionService,
		limiter: newIPRateLimiter(
			cfg.RateLimitPerIPPerSecond,
			float64(cfg.RateLimitBurst),
			cfg.RateLimitMaxTrackedIPs,
		),
		memoCache: newMemoResponseCache(cfg.MemoCacheTTL, cfg.MemoCacheMaxEntries),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.handleHealthz)
	mux.HandleFunc("GET /v1/config", h.handleConfig)
	mux.HandleFunc("GET /v1/deposit-memo", h.handleDepositMemo)
	mux.HandleFunc("POST /v1/deposits/submit", h.handleDepositSubmit)
	mux.HandleFunc("GET /v1/status/deposit/{depositId}", h.handleDepositStatus)
	mux.HandleFunc("POST /v1/withdrawals/request", h.handleWithdrawalRequest)
	mux.HandleFunc("GET /v1/status/withdrawal/{withdrawalId}", h.handleWithdrawalStatus)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health checks must never be throttled.
		if r.URL.Path == "/healthz" {
			mux.ServeHTTP(w, r)
			return
		}

		now := h.cfg.Now().UTC()
		ip := clientIP(r)
		allowed := h.limiter.Allow(ip, now)
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(h.cfg.RateLimitBurst))
		if !allowed {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"version": "v1",
				"error":   "rate_limited",
			})
			return
		}

		mux.ServeHTTP(w, r)
	}), nil
}

type handler struct {
	cfg Config

	deposits    DepositReader
	withdrawals WithdrawalReader
	actions     ActionService
	limiter     *ipRateLimiter
	memoCache   *memoResponseCache
}

func (h *handler) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (h *handler) handleConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":             "v1",
		"baseChainId":         h.cfg.BaseChainID,
		"bridgeAddress":       h.cfg.BridgeAddress.Hex(),
		"oWalletUA":           h.cfg.OWalletUA,
		"refundWindowSeconds": h.cfg.RefundWindowSeconds,
	})
}

func (h *handler) handleDepositMemo(w http.ResponseWriter, r *http.Request) {
	baseRecipientStr := strings.TrimSpace(r.URL.Query().Get("baseRecipient"))
	if !common.IsHexAddress(baseRecipientStr) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_base_recipient",
		})
		return
	}

	recipient := common.HexToAddress(baseRecipientStr)
	nonceQuery := strings.TrimSpace(r.URL.Query().Get("nonce"))
	cacheKey := memoCacheKey(strings.ToLower(recipient.Hex()), nonceQuery)
	if body, ok := h.memoCache.Get(cacheKey, h.cfg.Now().UTC()); ok {
		writeJSONBytes(w, http.StatusOK, body)
		return
	}

	nonce, err := parseNonce(nonceQuery, h.cfg.NonceFn)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_nonce",
		})
		return
	}

	var bridge [20]byte
	copy(bridge[:], h.cfg.BridgeAddress.Bytes())
	var recipient20 [20]byte
	copy(recipient20[:], recipient.Bytes())

	m := memo.DepositMemoV1{
		BaseChainID:   h.cfg.BaseChainID,
		BridgeAddr:    bridge,
		BaseRecipient: recipient20,
		Nonce:         nonce,
		Flags:         0,
	}
	encoded := m.Encode()

	resp := map[string]any{
		"version":       "v1",
		"baseChainId":   h.cfg.BaseChainID,
		"bridgeAddress": h.cfg.BridgeAddress.Hex(),
		"oWalletUA":     h.cfg.OWalletUA,
		"baseRecipient": recipient.Hex(),
		"nonce":         strconv.FormatUint(nonce, 10),
		"memoHex":       hex.EncodeToString(encoded[:]),
		"memoBase64":    base64.StdEncoding.EncodeToString(encoded[:]),
	}
	body, err := json.Marshal(resp)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"version": "v1",
			"error":   "internal",
		})
		return
	}
	body = append(body, '\n')
	h.memoCache.Set(cacheKey, body, h.cfg.Now().UTC())
	writeJSONBytes(w, http.StatusOK, body)
}

type depositSubmitRequestBody struct {
	BaseRecipient    string `json:"baseRecipient"`
	Amount           string `json:"amount"`
	Nonce            string `json:"nonce"`
	ProofWitnessItem string `json:"proofWitnessItem"`
}

func (h *handler) handleDepositSubmit(w http.ResponseWriter, r *http.Request) {
	if h.actions == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"version": "v1",
			"error":   "deposit_submit_unavailable",
		})
		return
	}

	body, ok := decodeJSONBody[depositSubmitRequestBody](w, r)
	if !ok {
		return
	}
	if !common.IsHexAddress(strings.TrimSpace(body.BaseRecipient)) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_base_recipient",
		})
		return
	}
	amount, err := parseUint64BodyValue(body.Amount)
	if err != nil || amount == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_amount",
		})
		return
	}
	nonce, err := parseUint64BodyValue(body.Nonce)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_nonce",
		})
		return
	}
	witnessItem, err := decodeHexBytes(body.ProofWitnessItem)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_proof_witness_item",
		})
		return
	}

	payload, err := h.actions.SubmitDeposit(r.Context(), DepositSubmitInput{
		BaseRecipient:    common.HexToAddress(strings.TrimSpace(body.BaseRecipient)),
		Amount:           amount,
		Nonce:            nonce,
		ProofWitnessItem: witnessItem,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"version": "v1",
			"error":   "submit_failed",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":   "v1",
		"queued":    true,
		"depositId": payload.DepositID,
		"amount":    strconv.FormatUint(payload.Amount, 10),
		"event":     payload,
	})
}

func (h *handler) handleDepositStatus(w http.ResponseWriter, r *http.Request) {
	id, err := parseHex32(r.PathValue("depositId"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_deposit_id",
		})
		return
	}

	job, err := h.deposits.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, deposit.ErrNotFound) {
			writeJSON(w, http.StatusOK, map[string]any{
				"version":   "v1",
				"found":     false,
				"depositId": "0x" + hex.EncodeToString(id[:]),
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"version": "v1",
			"error":   "internal",
		})
		return
	}

	txHash := ""
	if job.TxHash != ([32]byte{}) {
		txHash = "0x" + hex.EncodeToString(job.TxHash[:])
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":       "v1",
		"found":         true,
		"depositId":     "0x" + hex.EncodeToString(job.Deposit.DepositID[:]),
		"state":         job.State.String(),
		"amount":        strconv.FormatUint(job.Deposit.Amount, 10),
		"baseRecipient": "0x" + hex.EncodeToString(job.Deposit.BaseRecipient[:]),
		"txHash":        txHash,
	})
}

type withdrawalRequestBody struct {
	Amount                 string `json:"amount"`
	RecipientRawAddressHex string `json:"recipientRawAddressHex"`
}

func (h *handler) handleWithdrawalRequest(w http.ResponseWriter, r *http.Request) {
	if h.actions == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"version": "v1",
			"error":   "withdraw_request_unavailable",
		})
		return
	}

	body, ok := decodeJSONBody[withdrawalRequestBody](w, r)
	if !ok {
		return
	}
	amount, err := parseUint64BodyValue(body.Amount)
	if err != nil || amount == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_amount",
		})
		return
	}
	recipientUA, err := withdrawrequest.ParseFixedHex(body.RecipientRawAddressHex, 43)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_recipient_raw_address_hex",
		})
		return
	}
	payload, err := h.actions.RequestWithdrawal(r.Context(), WithdrawalRequestInput{
		Amount:      amount,
		RecipientUA: recipientUA,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"version": "v1",
			"error":   "request_failed",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":       "v1",
		"queued":        true,
		"withdrawalId":  payload.WithdrawalID,
		"requester":     payload.Requester,
		"amount":        strconv.FormatUint(payload.Amount, 10),
		"recipientUA":   payload.RecipientUA,
		"expiry":        strconv.FormatUint(payload.Expiry, 10),
		"feeBps":        payload.FeeBps,
		"approveTxHash": payload.ApproveTxHash,
		"requestTxHash": payload.RequestTxHash,
		"event":         payload,
	})
}

func (h *handler) handleWithdrawalStatus(w http.ResponseWriter, r *http.Request) {
	id, err := parseHex32(r.PathValue("withdrawalId"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_withdrawal_id",
		})
		return
	}

	st, err := h.withdrawals.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, withdraw.ErrNotFound) {
			writeJSON(w, http.StatusOK, map[string]any{
				"version":      "v1",
				"found":        false,
				"withdrawalId": "0x" + hex.EncodeToString(id[:]),
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"version": "v1",
			"error":   "internal",
		})
		return
	}

	state := "requested"
	batchID := ""
	if st.BatchID != nil {
		state = st.BatchState.String()
		batchID = "0x" + hex.EncodeToString(st.BatchID[:])
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":      "v1",
		"found":        true,
		"withdrawalId": "0x" + hex.EncodeToString(st.Withdrawal.ID[:]),
		"state":        state,
		"amount":       strconv.FormatUint(st.Withdrawal.Amount, 10),
		"feeBps":       st.Withdrawal.FeeBps,
		"requester":    "0x" + hex.EncodeToString(st.Withdrawal.Requester[:]),
		"expiry":       st.Withdrawal.Expiry.UTC().Format(time.RFC3339),
		"batchId":      batchID,
		"junoTxId":     st.JunoTxID,
		"baseTxHash":   st.BaseTxHash,
	})
}

func parseHex32(s string) ([32]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if len(s) != 64 {
		return [32]byte{}, fmt.Errorf("invalid length")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

func parseNonce(s string, fallback func() (uint64, error)) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback()
	}
	return strconv.ParseUint(s, 0, 64)
}

func randomNonce() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSONBody[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var out T
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_json",
		})
		return out, false
	}
	return out, true
}

func parseUint64BodyValue(raw string) (uint64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, errors.New("missing value")
	}
	return strconv.ParseUint(raw, 10, 64)
}

func decodeHexBytes(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "0x")
	raw = strings.TrimPrefix(raw, "0X")
	if raw == "" {
		return nil, errors.New("empty hex value")
	}
	return hex.DecodeString(raw)
}

func writeJSONBytes(w http.ResponseWriter, code int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func clientIP(r *http.Request) string {
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff != "" {
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return ip
		}
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	remote := strings.TrimSpace(r.RemoteAddr)
	if remote == "" {
		return "unknown"
	}
	if addr, err := netip.ParseAddrPort(remote); err == nil {
		return addr.Addr().String()
	}
	if addr, err := netip.ParseAddr(remote); err == nil {
		return addr.String()
	}
	host := remote
	if i := strings.LastIndex(remote, ":"); i > 0 {
		host = remote[:i]
	}
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return addr.String()
	}
	return remote
}

type limiterState struct {
	tokens   float64
	lastAt   time.Time
	lastSeen time.Time
}

type ipRateLimiter struct {
	mu sync.Mutex

	refillPerSecond float64
	burst           float64
	maxTrackedIPs   int
	states          map[string]limiterState
}

func newIPRateLimiter(refillPerSecond float64, burst float64, maxTrackedIPs int) *ipRateLimiter {
	return &ipRateLimiter{
		refillPerSecond: refillPerSecond,
		burst:           burst,
		maxTrackedIPs:   maxTrackedIPs,
		states:          make(map[string]limiterState),
	}
}

func (l *ipRateLimiter) Allow(ip string, now time.Time) bool {
	if l == nil {
		return true
	}
	if ip == "" {
		ip = "unknown"
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	st, ok := l.states[ip]
	if !ok {
		if len(l.states) >= l.maxTrackedIPs {
			l.evictOne()
		}
		l.states[ip] = limiterState{
			tokens:   l.burst - 1,
			lastAt:   now,
			lastSeen: now,
		}
		return true
	}

	elapsed := now.Sub(st.lastAt).Seconds()
	if elapsed > 0 {
		st.tokens += elapsed * l.refillPerSecond
		if st.tokens > l.burst {
			st.tokens = l.burst
		}
	}
	st.lastAt = now
	st.lastSeen = now

	if st.tokens < 1 {
		l.states[ip] = st
		return false
	}
	st.tokens -= 1
	l.states[ip] = st
	return true
}

func (l *ipRateLimiter) evictOne() {
	var oldestIP string
	var oldestAt time.Time
	first := true
	for ip, st := range l.states {
		if first || st.lastSeen.Before(oldestAt) {
			oldestIP = ip
			oldestAt = st.lastSeen
			first = false
		}
	}
	if oldestIP != "" {
		delete(l.states, oldestIP)
	}
}

type memoEntry struct {
	body      []byte
	expiresAt time.Time
	lastSeen  time.Time
}

type memoResponseCache struct {
	mu sync.Mutex

	ttl        time.Duration
	maxEntries int
	entries    map[string]memoEntry
}

func newMemoResponseCache(ttl time.Duration, maxEntries int) *memoResponseCache {
	return &memoResponseCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		entries:    make(map[string]memoEntry),
	}
}

func (c *memoResponseCache) Get(key string, now time.Time) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !now.Before(e.expiresAt) {
		delete(c.entries, key)
		return nil, false
	}
	e.lastSeen = now
	c.entries[key] = e
	return append([]byte(nil), e.body...), true
}

func (c *memoResponseCache) Set(key string, body []byte, now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneExpired(now)
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxEntries {
		c.evictOne()
	}

	c.entries[key] = memoEntry{
		body:      append([]byte(nil), body...),
		expiresAt: now.Add(c.ttl),
		lastSeen:  now,
	}
}

func (c *memoResponseCache) pruneExpired(now time.Time) {
	for k, v := range c.entries {
		if !now.Before(v.expiresAt) {
			delete(c.entries, k)
		}
	}
}

func (c *memoResponseCache) evictOne() {
	var evictKey string
	var oldest time.Time
	first := true
	for k, v := range c.entries {
		if first || v.lastSeen.Before(oldest) {
			first = false
			oldest = v.lastSeen
			evictKey = k
		}
	}
	if evictKey != "" {
		delete(c.entries, evictKey)
	}
}

func memoCacheKey(baseRecipient string, nonce string) string {
	return baseRecipient + "|" + nonce
}
