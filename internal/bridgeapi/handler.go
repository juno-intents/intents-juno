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
	"github.com/juno-intents/intents-juno/internal/bridgeconfig"
	"github.com/juno-intents/intents-juno/internal/deposit"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/runtimeconfig"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

var ErrInvalidConfig = errors.New("bridgeapi: invalid config")

type Config struct {
	BaseChainID                   uint32
	BridgeAddress                 common.Address
	WJunoAddress                  common.Address
	OWalletUA                     string
	WithdrawalExpiryWindowSeconds uint64
	MinDepositAmount              uint64
	DepositMinConfirmations       int64
	MinWithdrawAmount             uint64
	FeeBps                        uint32
	NonceFn                       func() (uint64, error)

	RuntimeSettings RuntimeSettingsProvider
	BridgeSettings  BridgeSettingsProvider
	JunoTipProvider JunoTipProvider

	RateLimitPerIPPerSecond float64
	RateLimitBurst          int
	RateLimitMaxTrackedIPs  int

	MemoCacheTTL        time.Duration
	MemoCacheMaxEntries int

	DepositLister    DepositLister
	WithdrawalLister WithdrawalLister
	ReadinessCheck   func(context.Context) error

	Now func() time.Time
}

type RuntimeSettingsProvider interface {
	Current() (runtimeconfig.Settings, error)
}

type BridgeSettingsProvider interface {
	Current() (bridgeconfig.Snapshot, error)
}

type JunoTipProvider interface {
	TipHeight(ctx context.Context) (int64, error)
}

type DepositStatus struct {
	Job        deposit.Job
	BaseTxHash string
	CreatedAt  time.Time
}

type DepositReader interface {
	Get(ctx context.Context, depositID [32]byte) (DepositStatus, error)
}

type WithdrawalStatus struct {
	Withdrawal withdraw.Withdrawal
	BatchID    *[32]byte
	BatchState withdraw.BatchState
	JunoTxID   string
	BaseTxHash string
	CreatedAt  time.Time
}

type WithdrawalReader interface {
	Get(ctx context.Context, withdrawalID [32]byte) (WithdrawalStatus, error)
}

type DepositLister interface {
	ListByBaseRecipient(ctx context.Context, recipient [20]byte, limit, offset int) ([]DepositStatus, int, error)
	GetByTxHash(ctx context.Context, txHash [32]byte) (*DepositStatus, error)
	ListRecent(ctx context.Context, limit, offset int) ([]DepositStatus, int, error)
}

type WithdrawalLister interface {
	ListByRequester(ctx context.Context, requester [20]byte, limit, offset int) ([]WithdrawalStatus, int, error)
	GetByJunoTxID(ctx context.Context, junoTxID string) ([]WithdrawalStatus, error)
	GetByBaseTxHash(ctx context.Context, baseTxHash string) ([]WithdrawalStatus, error)
	ListRecent(ctx context.Context, limit, offset int) ([]WithdrawalStatus, int, error)
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
		cfg:              cfg,
		deposits:         deposits,
		withdrawals:      withdrawals,
		depositLister:    cfg.DepositLister,
		withdrawalLister: cfg.WithdrawalLister,
		limiter: newIPRateLimiter(
			cfg.RateLimitPerIPPerSecond,
			float64(cfg.RateLimitBurst),
			cfg.RateLimitMaxTrackedIPs,
		),
		memoCache: newMemoResponseCache(cfg.MemoCacheTTL, cfg.MemoCacheMaxEntries),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", h.handleHealthz)
	mux.HandleFunc("GET /healthz", h.handleHealthz)
	mux.HandleFunc("GET /readyz", h.handleHealthz)
	mux.HandleFunc("GET /v1/config", h.handleConfig)
	mux.HandleFunc("GET /v1/deposit-memo", h.handleDepositMemo)
	mux.HandleFunc("GET /v1/status/deposit/{depositId}", h.handleDepositStatus)
	mux.HandleFunc("GET /v1/status/withdrawal/{withdrawalId}", h.handleWithdrawalStatus)
	mux.HandleFunc("GET /v1/deposits", h.handleListDeposits)
	mux.HandleFunc("GET /v1/withdrawals", h.handleListWithdrawals)
	mux.HandleFunc("GET /v1/deposits/recent", h.handleListRecentDeposits)
	mux.HandleFunc("GET /v1/withdrawals/recent", h.handleListRecentWithdrawals)
	mux.HandleFunc("GET /v1/decode-recipient", h.handleDecodeRecipient)

	// SPA frontend fallback: serve embedded frontend for non-API paths.
	frontendHandler := FrontendHandler()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Only serve frontend for paths that don't match API routes.
		if strings.HasPrefix(r.URL.Path, "/v1/") || isProbePath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		frontendHandler.ServeHTTP(w, r)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health checks must never be throttled.
		if isProbePath(r.URL.Path) {
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

func isProbePath(path string) bool {
	return path == "/healthz" || path == "/livez" || path == "/readyz"
}

type handler struct {
	cfg Config

	deposits         DepositReader
	withdrawals      WithdrawalReader
	depositLister    DepositLister
	withdrawalLister WithdrawalLister
	limiter          *ipRateLimiter
	memoCache        *memoResponseCache
}

func (h *handler) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/readyz" && h.cfg.ReadinessCheck != nil {
		if err := h.cfg.ReadinessCheck(r.Context()); err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not_ready\n"))
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (h *handler) handleConfig(w http.ResponseWriter, _ *http.Request) {
	minDepositAmount, err := h.currentMinDepositAmount()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"version": "v1",
			"error":   "bridge_settings_not_ready",
		})
		return
	}
	depositMinConfirmations, err := h.currentDepositMinConfirmations()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"version": "v1",
			"error":   "runtime_settings_not_ready",
		})
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	resp := map[string]any{
		"version":                       "v1",
		"baseChainId":                   h.cfg.BaseChainID,
		"bridgeAddress":                 h.cfg.BridgeAddress.Hex(),
		"oWalletUA":                     h.cfg.OWalletUA,
		"withdrawalExpiryWindowSeconds": h.cfg.WithdrawalExpiryWindowSeconds,
		"minDepositAmount":              strconv.FormatUint(minDepositAmount, 10),
		"depositMinConfirmations":       depositMinConfirmations,
		"minWithdrawAmount":             strconv.FormatUint(h.cfg.MinWithdrawAmount, 10),
		"feeBps":                        h.cfg.FeeBps,
	}
	if h.cfg.WJunoAddress != (common.Address{}) {
		resp["wjunoAddress"] = h.cfg.WJunoAddress.Hex()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *handler) currentMinDepositAmount() (uint64, error) {
	if h.cfg.BridgeSettings == nil {
		return h.cfg.MinDepositAmount, nil
	}
	snapshot, err := h.cfg.BridgeSettings.Current()
	if err != nil {
		return 0, err
	}
	return snapshot.MinDepositAmount, nil
}

func (h *handler) currentDepositMinConfirmations() (int64, error) {
	if h.cfg.RuntimeSettings == nil {
		return h.cfg.DepositMinConfirmations, nil
	}
	settings, err := h.cfg.RuntimeSettings.Current()
	if err != nil {
		return 0, err
	}
	return settings.DepositMinConfirmations, nil
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

	writeJSON(w, http.StatusOK, depositStatusPayload("0x"+hex.EncodeToString(id[:]), job, h.depositProgress(r.Context(), job)))
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
		"createdAt":    formatOptionalTime(st.CreatedAt),
	})
}

func (h *handler) depositProgress(ctx context.Context, st DepositStatus) depositConfirmationProgress {
	progress := depositConfirmationProgress{}
	required, err := h.currentDepositMinConfirmations()
	if err == nil && required > 0 {
		progress.RequiredConfirmations = required
	}
	if h.cfg.JunoTipProvider == nil || st.Job.Deposit.JunoHeight <= 0 {
		return progress
	}
	tipHeight, err := h.cfg.JunoTipProvider.TipHeight(ctx)
	if err != nil || tipHeight < st.Job.Deposit.JunoHeight {
		return progress
	}
	progress.Confirmations = tipHeight - st.Job.Deposit.JunoHeight + 1
	return progress
}

type depositConfirmationProgress struct {
	Confirmations         int64
	RequiredConfirmations int64
}

func depositStatusPayload(id string, st DepositStatus, progress depositConfirmationProgress) map[string]any {
	txHash := ""
	if st.Job.TxHash != ([32]byte{}) {
		txHash = "0x" + hex.EncodeToString(st.Job.TxHash[:])
	}

	out := map[string]any{
		"version":         "v1",
		"found":           true,
		"depositId":       id,
		"state":           st.Job.State.String(),
		"amount":          strconv.FormatUint(st.Job.Deposit.Amount, 10),
		"baseRecipient":   "0x" + hex.EncodeToString(st.Job.Deposit.BaseRecipient[:]),
		"txHash":          txHash,
		"baseTxHash":      st.BaseTxHash,
		"createdAt":       formatOptionalTime(st.CreatedAt),
		"rejectionReason": st.Job.RejectionReason,
	}
	if progress.RequiredConfirmations > 0 {
		out["requiredConfirmations"] = progress.RequiredConfirmations
	}
	if progress.Confirmations > 0 {
		out["confirmations"] = progress.Confirmations
	}
	return out
}

func (h *handler) handleDecodeRecipient(w http.ResponseWriter, r *http.Request) {
	ua := strings.TrimSpace(r.URL.Query().Get("ua"))
	if ua == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "missing_ua_param",
		})
		return
	}
	raw, err := DecodeOrchardRawFromUA(ua)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_unified_address",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":         "v1",
		"orchardReceiver": hex.EncodeToString(raw),
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

func writeJSONBytes(w http.ResponseWriter, code int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// clientIP extracts the client IP from r.RemoteAddr only. We do not trust
// X-Forwarded-For or X-Real-IP because the NLB preserves the real client IP
// at L4, and trusting proxy headers allows rate-limit bypass via spoofing.
func clientIP(r *http.Request) string {
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

func formatOptionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
