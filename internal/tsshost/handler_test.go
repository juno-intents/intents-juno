package tsshost

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/tss"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

type stubSigner struct {
	calls int

	ret []byte
}

func (s *stubSigner) Sign(_ context.Context, _ [32]byte, _ [32]byte, _ []byte) ([]byte, error) {
	s.calls++
	return append([]byte(nil), s.ret...), nil
}

type stubVerifier struct {
	calls     int
	sessionID [32]byte
	batchID   [32]byte
	txPlan    []byte
	err       error
}

func (v *stubVerifier) VerifySignRequest(_ context.Context, sessionID [32]byte, batchID [32]byte, txPlan []byte) error {
	v.calls++
	v.sessionID = sessionID
	v.batchID = batchID
	v.txPlan = append([]byte(nil), txPlan...)
	return v.err
}

func seq32(start byte) (out [32]byte) {
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
}

func TestHandler_ProbePaths(t *testing.T) {
	t.Parallel()

	h := NewHandler(&stubSigner{ret: []byte("signed")}, Config{
		MaxBodyBytes:   1 << 20,
		MaxTxPlanBytes: 1 << 20,
		MaxSessions:    16,
		Now:            time.Now,
	})

	for _, path := range []string{"/livez", "/readyz", "/healthz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status: got %d want %d", path, rec.Code, http.StatusOK)
		}
	}
}

func TestHandler_ReadyzReflectsReadinessCheck(t *testing.T) {
	t.Parallel()

	h := NewHandler(&stubSigner{ret: []byte("signed")}, Config{
		MaxBodyBytes:   1 << 20,
		MaxTxPlanBytes: 1 << 20,
		MaxSessions:    16,
		Now:            time.Now,
		ReadinessCheck: func(context.Context) error {
			return errors.New("signer unavailable")
		},
	})

	readyReq := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	readyRec := httptest.NewRecorder()
	h.ServeHTTP(readyRec, readyReq)
	if readyRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status: got %d want %d", readyRec.Code, http.StatusServiceUnavailable)
	}

	liveReq := httptest.NewRequest(http.MethodGet, "/livez", nil)
	liveRec := httptest.NewRecorder()
	h.ServeHTTP(liveRec, liveReq)
	if liveRec.Code != http.StatusOK {
		t.Fatalf("/livez status: got %d want %d", liveRec.Code, http.StatusOK)
	}
}

func TestHandler_Sign_IdempotentPerSession(t *testing.T) {
	t.Parallel()

	signer := &stubSigner{ret: []byte("signed")}
	h := NewHandler(signer, Config{
		MaxBodyBytes:   1 << 20,
		MaxTxPlanBytes: 1 << 20,
		MaxSessions:    16,
		Now:            func() time.Time { return time.Unix(0, 0).UTC() },
	})

	sessionID := seq32(0x10)
	batchID := seq32(0x11)
	txPlan := []byte("plan-v1")

	body, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionID[:]),
		"batchId":   "0x" + hex.EncodeToString(batchID[:]),
		"txPlan":    txPlan,
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Same request must not call the signer again.
	req2 := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	if signer.calls != 1 {
		t.Fatalf("expected 1 signer call, got %d", signer.calls)
	}

	var out struct {
		Version   string `json:"version"`
		SessionID string `json:"sessionId"`
		SignedTx  []byte `json:"signedTx"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if out.Version != "tss.sign_result.v1" {
		t.Fatalf("unexpected version: %q", out.Version)
	}
	if out.SessionID != "0x"+hex.EncodeToString(sessionID[:]) {
		t.Fatalf("unexpected session id: %q", out.SessionID)
	}
	if string(out.SignedTx) != "signed" {
		t.Fatalf("unexpected signed tx: %q", string(out.SignedTx))
	}
}

func TestHandler_Sign_ConflictOnSameSessionDifferentTxPlan(t *testing.T) {
	t.Parallel()

	signer := &stubSigner{ret: []byte("signed")}
	h := NewHandler(signer, Config{MaxBodyBytes: 1 << 20, MaxTxPlanBytes: 1 << 20, MaxSessions: 16, Now: time.Now})

	sessionID := seq32(0x20)
	batchID := seq32(0x21)

	bodyA, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionID[:]),
		"batchId":   "0x" + hex.EncodeToString(batchID[:]),
		"txPlan":    []byte("plan-a"),
	})
	if err != nil {
		t.Fatalf("json.Marshal A: %v", err)
	}
	bodyB, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionID[:]),
		"batchId":   "0x" + hex.EncodeToString(batchID[:]),
		"txPlan":    []byte("plan-b"),
	})
	if err != nil {
		t.Fatalf("json.Marshal B: %v", err)
	}

	recA := httptest.NewRecorder()
	h.ServeHTTP(recA, httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(bodyA)))
	if recA.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recA.Code, recA.Body.String())
	}

	recB := httptest.NewRecorder()
	h.ServeHTTP(recB, httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(bodyB)))
	if recB.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", recB.Code, recB.Body.String())
	}
	if signer.calls != 1 {
		t.Fatalf("expected 1 signer call, got %d", signer.calls)
	}
}

func TestHandler_MetricsSnapshotReflectsTrackedSessions(t *testing.T) {
	t.Parallel()

	signer := &stubSigner{ret: []byte("signed")}
	h := NewHandler(signer, Config{
		MaxBodyBytes:   1 << 20,
		MaxTxPlanBytes: 1 << 20,
		MaxSessions:    2,
		Now:            func() time.Time { return time.Unix(0, 0).UTC() },
	})

	reporter, ok := h.(interface{ MetricsSnapshot() MetricsSnapshot })
	if !ok {
		t.Fatalf("handler does not expose MetricsSnapshot")
	}

	snapshot := reporter.MetricsSnapshot()
	if snapshot.SessionCount != 0 || snapshot.SessionCapacity != 2 {
		t.Fatalf("initial snapshot = %#v, want zero active sessions with capacity 2", snapshot)
	}

	sessionID := seq32(0x44)
	batchID := seq32(0x45)
	body, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionID[:]),
		"batchId":   "0x" + hex.EncodeToString(batchID[:]),
		"txPlan":    []byte("plan-v1"),
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	snapshot = reporter.MetricsSnapshot()
	if snapshot.SessionCount != 1 || snapshot.SessionCapacity != 2 {
		t.Fatalf("snapshot after sign = %#v, want one active session with capacity 2", snapshot)
	}
}

func TestHandler_Sign_BadRequestOnInvalidSessionID(t *testing.T) {
	t.Parallel()

	signer := &stubSigner{ret: []byte("signed")}
	h := NewHandler(signer, Config{MaxBodyBytes: 1 << 20, MaxTxPlanBytes: 1 << 20, MaxSessions: 16, Now: time.Now})
	batchID := seq32(0x31)

	body, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x1234",
		"batchId":   "0x" + hex.EncodeToString(batchID[:]),
		"txPlan":    []byte("plan"),
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if signer.calls != 0 {
		t.Fatalf("expected 0 signer calls, got %d", signer.calls)
	}
}

func TestHandler_Sign_PayloadTooLargeOnTxPlanLimit(t *testing.T) {
	t.Parallel()

	signer := &stubSigner{ret: []byte("signed")}
	h := NewHandler(signer, Config{MaxBodyBytes: 1 << 20, MaxTxPlanBytes: 3, MaxSessions: 16, Now: time.Now})

	sessionID := seq32(0x30)
	batchID := seq32(0x31)
	body, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionID[:]),
		"batchId":   "0x" + hex.EncodeToString(batchID[:]),
		"txPlan":    []byte("toolong"),
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body)))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", rec.Code, rec.Body.String())
	}
	if signer.calls != 0 {
		t.Fatalf("expected 0 signer calls, got %d", signer.calls)
	}
}

func TestHandler_Sign_BadRequestOnInvalidBatchID(t *testing.T) {
	t.Parallel()

	signer := &stubSigner{ret: []byte("signed")}
	h := NewHandler(signer, Config{MaxBodyBytes: 1 << 20, MaxTxPlanBytes: 1 << 20, MaxSessions: 16, Now: time.Now})
	sessionID := seq32(0x61)

	body, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionID[:]),
		"batchId":   "0x1234",
		"txPlan":    []byte("plan"),
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if signer.calls != 0 {
		t.Fatalf("expected 0 signer calls, got %d", signer.calls)
	}
}

func TestHandler_Sign_VerifiesBatchBindingBeforeSigning(t *testing.T) {
	t.Parallel()

	signer := &stubSigner{ret: []byte("signed")}
	verifier := &stubVerifier{}
	batchID := seq32(0x72)
	txPlan := []byte(`{"version":"v0"}`)
	sessionID := tss.DeriveSigningSessionID(batchID, txPlan)
	h := NewHandler(signer, Config{
		MaxBodyBytes:   1 << 20,
		MaxTxPlanBytes: 1 << 20,
		MaxSessions:    16,
		Now:            time.Now,
		Verifier:       verifier,
	})

	body, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": tss.FormatSessionID(sessionID),
		"batchId":   tss.FormatBatchID(batchID),
		"txPlan":    txPlan,
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if signer.calls != 1 {
		t.Fatalf("expected 1 signer call, got %d", signer.calls)
	}
	if verifier.calls != 1 {
		t.Fatalf("expected 1 verifier call, got %d", verifier.calls)
	}
	if verifier.sessionID != sessionID {
		t.Fatalf("sessionID mismatch")
	}
	if verifier.batchID != batchID {
		t.Fatalf("batchID mismatch")
	}
	if !bytes.Equal(verifier.txPlan, txPlan) {
		t.Fatalf("txPlan mismatch")
	}
}

func TestHandler_Sign_RequiresBearerAuthWhenConfigured(t *testing.T) {
	t.Parallel()

	signer := &stubSigner{ret: []byte("signed")}
	batchID := seq32(0x73)
	txPlan := []byte(`{"version":"v0","kind":"withdrawal","change_address":"jtest1change000000000000000000000000000000000000000000000000000000","outputs":[]}`)
	sessionID := tss.DeriveSigningSessionID(batchID, txPlan)
	h := NewHandler(signer, Config{
		MaxBodyBytes:   1 << 20,
		MaxTxPlanBytes: 1 << 20,
		MaxSessions:    16,
		Now:            time.Now,
		AuthToken:      "secret-token",
	})

	body, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": tss.FormatSessionID(sessionID),
		"batchId":   tss.FormatBatchID(batchID),
		"txPlan":    txPlan,
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
	if signer.calls != 0 {
		t.Fatalf("expected 0 signer calls, got %d", signer.calls)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if signer.calls != 1 {
		t.Fatalf("expected 1 signer call, got %d", signer.calls)
	}
}

func TestHandler_Sign_BadRequestOnInvalidJSON(t *testing.T) {
	t.Parallel()

	signer := &stubSigner{ret: []byte("signed")}
	h := NewHandler(signer, Config{MaxBodyBytes: 1 << 20, MaxTxPlanBytes: 1 << 20, MaxSessions: 16, Now: time.Now})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader([]byte("not-json"))))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_Sign_BadRequestOnTrailingJSON(t *testing.T) {
	t.Parallel()

	signer := &stubSigner{ret: []byte("signed")}
	h := NewHandler(signer, Config{MaxBodyBytes: 1 << 20, MaxTxPlanBytes: 1 << 20, MaxSessions: 16, Now: time.Now})

	sessionID := seq32(0x40)
	batchID := seq32(0x41)
	body, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionID[:]),
		"batchId":   "0x" + hex.EncodeToString(batchID[:]),
		"txPlan":    []byte("plan"),
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	body = append(body, '\n')
	body = append(body, []byte(`{"extra":true}`)...)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if signer.calls != 0 {
		t.Fatalf("expected 0 signer calls, got %d", signer.calls)
	}
}

func TestHandler_Sign_EvictsExpiredCompletedSessions(t *testing.T) {
	t.Parallel()

	var now time.Time
	signer := &stubSigner{ret: []byte("signed")}
	h := NewHandler(signer, Config{
		MaxBodyBytes:   1 << 20,
		MaxTxPlanBytes: 1 << 20,
		MaxSessions:    1,
		SessionTTL:     time.Second,
		Now:            func() time.Time { return now },
	})

	now = time.Unix(100, 0).UTC()
	sessionIDA := seq32(0x50)
	batchIDA := seq32(0x51)
	bodyA, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionIDA[:]),
		"batchId":   "0x" + hex.EncodeToString(batchIDA[:]),
		"txPlan":    []byte("plan-a"),
	})
	if err != nil {
		t.Fatalf("json.Marshal A: %v", err)
	}
	recA := httptest.NewRecorder()
	h.ServeHTTP(recA, httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(bodyA)))
	if recA.Code != http.StatusOK {
		t.Fatalf("expected first request to succeed, got %d: %s", recA.Code, recA.Body.String())
	}

	now = now.Add(2 * time.Second)
	sessionIDB := seq32(0x60)
	batchIDB := seq32(0x61)
	bodyB, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionIDB[:]),
		"batchId":   "0x" + hex.EncodeToString(batchIDB[:]),
		"txPlan":    []byte("plan-b"),
	})
	if err != nil {
		t.Fatalf("json.Marshal B: %v", err)
	}
	recB := httptest.NewRecorder()
	h.ServeHTTP(recB, httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(bodyB)))
	if recB.Code != http.StatusOK {
		t.Fatalf("expected second request to succeed after eviction, got %d: %s", recB.Code, recB.Body.String())
	}
	if signer.calls != 2 {
		t.Fatalf("expected 2 signer calls, got %d", signer.calls)
	}
}

func TestHandler_Sign_AuditLogsRequests(t *testing.T) {
	t.Parallel()

	handler := &captureHandler{}
	log := slog.New(handler)
	signer := &stubSigner{ret: []byte("signed")}
	h := NewHandler(signer, Config{
		MaxBodyBytes:   1 << 20,
		MaxTxPlanBytes: 1 << 20,
		MaxSessions:    16,
		Now:            func() time.Time { return time.Unix(200, 0).UTC() },
		Log:            log,
	})

	sessionID := seq32(0x70)
	batchID := seq32(0x71)
	body, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionID[:]),
		"batchId":   "0x" + hex.EncodeToString(batchID[:]),
		"txPlan":    []byte("plan-a"),
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	records := handler.records()
	if len(records) == 0 {
		t.Fatalf("expected at least one audit record")
	}
	got := records[len(records)-1]
	if got.msg != "tsshost sign request" {
		t.Fatalf("unexpected log message: %q", got.msg)
	}
	if got.attrs["result"] != "new_session" {
		t.Fatalf("result: got %q want %q", got.attrs["result"], "new_session")
	}
	if got.attrs["session_id"] == "" {
		t.Fatalf("expected session_id in audit log")
	}
}

func TestWithdrawBatchVerifier_RejectsMismatchedSessionBinding(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	store := withdraw.NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()
	w := withdraw.Withdrawal{
		ID:          seq32(0x80),
		Requester:   [20]byte{0x01},
		Amount:      5,
		RecipientUA: bytes.Repeat([]byte{0x11}, 43),
		Expiry:      now.Add(24 * time.Hour),
	}
	if _, _, err := store.UpsertRequested(ctx, w); err != nil {
		t.Fatalf("UpsertRequested: %v", err)
	}
	if _, err := store.ClaimUnbatched(ctx, withdraw.Fence{Owner: "a", LeaseVersion: 1}, time.Minute, 1); err != nil {
		t.Fatalf("ClaimUnbatched: %v", err)
	}
	batchID := seq32(0x81)
	txPlan := []byte(`{"kind":"send-many"}`)
	if err := store.CreatePlannedBatch(ctx, withdraw.Fence{Owner: "a", LeaseVersion: 1}, withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        txPlan,
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}

	verifier := NewWithdrawBatchVerifier(store, WithdrawBatchVerifierConfig{
		BaseChainID:  8453,
		BridgeAddress: common.HexToAddress("0x00000000000000000000000000000000000000b7"),
	})
	err := verifier.VerifySignRequest(ctx, seq32(0x82), batchID, txPlan)
	if err == nil {
		t.Fatalf("expected verifier rejection")
	}
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("expected ErrRejected, got %v", err)
	}
}

type captureHandler struct {
	mu   sync.Mutex
	recs []capturedRecord
}

type capturedRecord struct {
	msg   string
	attrs map[string]string
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, record slog.Record) error {
	out := capturedRecord{
		msg:   record.Message,
		attrs: map[string]string{},
	}
	record.Attrs(func(attr slog.Attr) bool {
		out.attrs[attr.Key] = attr.Value.String()
		return true
	})
	h.mu.Lock()
	h.recs = append(h.recs, out)
	h.mu.Unlock()
	return nil
}

func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler        { return h }

func (h *captureHandler) records() []capturedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]capturedRecord, len(h.recs))
	copy(out, h.recs)
	return out
}
