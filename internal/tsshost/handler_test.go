package tsshost

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type stubSigner struct {
	calls int

	ret []byte
}

func (s *stubSigner) Sign(_ context.Context, _ [32]byte, _ []byte) ([]byte, error) {
	s.calls++
	return append([]byte(nil), s.ret...), nil
}

func seq32(start byte) (out [32]byte) {
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
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
	txPlan := []byte("plan-v1")

	body, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionID[:]),
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

	bodyA, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionID[:]),
		"txPlan":    []byte("plan-a"),
	})
	if err != nil {
		t.Fatalf("json.Marshal A: %v", err)
	}
	bodyB, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionID[:]),
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

func TestHandler_Sign_BadRequestOnInvalidSessionID(t *testing.T) {
	t.Parallel()

	signer := &stubSigner{ret: []byte("signed")}
	h := NewHandler(signer, Config{MaxBodyBytes: 1 << 20, MaxTxPlanBytes: 1 << 20, MaxSessions: 16, Now: time.Now})

	body, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x1234",
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
	body, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionID[:]),
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
	body, err := json.Marshal(map[string]any{
		"version":   "tss.sign.v1",
		"sessionId": "0x" + hex.EncodeToString(sessionID[:]),
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
