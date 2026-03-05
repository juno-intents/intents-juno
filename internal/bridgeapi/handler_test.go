package bridgeapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/deposit"
	"github.com/juno-intents/intents-juno/internal/depositevent"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

type stubDepositReader struct {
	job deposit.Job
	err error
}

func (s *stubDepositReader) Get(_ context.Context, _ [32]byte) (deposit.Job, error) {
	return s.job, s.err
}

type stubWithdrawalReader struct {
	status WithdrawalStatus
	err    error
}

func (s *stubWithdrawalReader) Get(_ context.Context, _ [32]byte) (WithdrawalStatus, error) {
	return s.status, s.err
}

type stubDepositLister struct {
	jobs  []deposit.Job
	total int
	job   *deposit.Job
	err   error
}

func (s *stubDepositLister) ListByBaseRecipient(_ context.Context, _ [20]byte, _, _ int) ([]deposit.Job, int, error) {
	return s.jobs, s.total, s.err
}

func (s *stubDepositLister) GetByTxHash(_ context.Context, _ [32]byte) (*deposit.Job, error) {
	return s.job, s.err
}

type stubWithdrawalLister struct {
	statuses []WithdrawalStatus
	total    int
	err      error
}

func (s *stubWithdrawalLister) ListByRequester(_ context.Context, _ [20]byte, _, _ int) ([]WithdrawalStatus, int, error) {
	return s.statuses, s.total, s.err
}

func (s *stubWithdrawalLister) GetByJunoTxID(_ context.Context, _ string) ([]WithdrawalStatus, error) {
	return s.statuses, s.err
}

func (s *stubWithdrawalLister) GetByBaseTxHash(_ context.Context, _ string) ([]WithdrawalStatus, error) {
	return s.statuses, s.err
}

type stubActionService struct {
	depositReq  DepositSubmitInput
	depositResp depositevent.Payload
	depositErr  error
}

func (s *stubActionService) SubmitDeposit(_ context.Context, req DepositSubmitInput) (depositevent.Payload, error) {
	s.depositReq = req
	return s.depositResp, s.depositErr
}

func TestHandler_Config(t *testing.T) {
	t.Parallel()

	h, err := NewHandler(Config{
		BaseChainID:         8453,
		BridgeAddress:       common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
		OWalletUA:           "u1example",
		RefundWindowSeconds: 86400,
		NonceFn: func() (uint64, error) {
			return 1, nil
		},
	}, &stubDepositReader{}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusOK)
	}

	var out struct {
		Version             string `json:"version"`
		BaseChainID         uint32 `json:"baseChainId"`
		BridgeAddress       string `json:"bridgeAddress"`
		OWalletUA           string `json:"oWalletUA"`
		RefundWindowSeconds uint64 `json:"refundWindowSeconds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Version != "v1" || out.BaseChainID != 8453 || out.RefundWindowSeconds != 86400 {
		t.Fatalf("bad config response: %+v", out)
	}
}

func TestHandler_DepositMemo(t *testing.T) {
	t.Parallel()

	h, err := NewHandler(Config{
		BaseChainID:         8453,
		BridgeAddress:       common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
		OWalletUA:           "u1example",
		RefundWindowSeconds: 86400,
		NonceFn: func() (uint64, error) {
			return 0x0102030405060708, nil
		},
	}, &stubDepositReader{}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/deposit-memo?baseRecipient=0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var out struct {
		Version       string `json:"version"`
		BaseRecipient string `json:"baseRecipient"`
		MemoHex       string `json:"memoHex"`
		Nonce         string `json:"nonce"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Version != "v1" || strings.ToLower(out.BaseRecipient) != "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1" {
		t.Fatalf("bad response: %+v", out)
	}
	if out.Nonce != "72623859790382856" {
		t.Fatalf("unexpected nonce: %s", out.Nonce)
	}
	memoRaw, err := hex.DecodeString(out.MemoHex)
	if err != nil {
		t.Fatalf("decode memo hex: %v", err)
	}
	if len(memoRaw) != 512 {
		t.Fatalf("memo length: got %d want 512", len(memoRaw))
	}
}

func TestHandler_DepositStatus_NotFound(t *testing.T) {
	t.Parallel()

	h, err := NewHandler(Config{
		BaseChainID:         8453,
		BridgeAddress:       common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
		OWalletUA:           "u1example",
		RefundWindowSeconds: 86400,
		NonceFn: func() (uint64, error) {
			return 1, nil
		},
	}, &stubDepositReader{err: deposit.ErrNotFound}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/status/deposit/0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusOK)
	}

	var out struct {
		Found bool `json:"found"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Found {
		t.Fatalf("expected found=false")
	}
}

func TestHandler_WithdrawalStatus(t *testing.T) {
	t.Parallel()

	var wid [32]byte
	wid[0] = 0x11
	var batchID [32]byte
	batchID[0] = 0x22

	h, err := NewHandler(Config{
		BaseChainID:         8453,
		BridgeAddress:       common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
		OWalletUA:           "u1example",
		RefundWindowSeconds: 86400,
		NonceFn: func() (uint64, error) {
			return 1, nil
		},
	}, &stubDepositReader{}, &stubWithdrawalReader{
		status: WithdrawalStatus{
			Withdrawal: withdraw.Withdrawal{
				ID:        wid,
				Amount:    100,
				FeeBps:    50,
				Expiry:    time.Unix(1_700_000_000, 0).UTC(),
				Requester: [20]byte{0x33},
			},
			BatchID:    &batchID,
			BatchState: withdraw.BatchStateBroadcasted,
			JunoTxID:   "abc",
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/status/withdrawal/0x1100000000000000000000000000000000000000000000000000000000000000", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var out struct {
		Found  bool   `json:"found"`
		State  string `json:"state"`
		JunoTx string `json:"junoTxId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Found || out.State != "broadcasted" || out.JunoTx != "abc" {
		t.Fatalf("bad response: %+v", out)
	}
}

func TestHandler_DepositMemo_CacheHitUsesSingleNonce(t *testing.T) {
	t.Parallel()

	var nonceCalls atomic.Uint64
	h, err := NewHandler(Config{
		BaseChainID:         8453,
		BridgeAddress:       common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
		OWalletUA:           "u1example",
		RefundWindowSeconds: 86400,
		MemoCacheTTL:        30 * time.Second,
		NonceFn: func() (uint64, error) {
			return nonceCalls.Add(1), nil
		},
	}, &stubDepositReader{}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	path := "/v1/deposit-memo?baseRecipient=0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1"

	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, path, nil)
	req1.RemoteAddr = "203.0.113.10:12345"
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first status: got %d want %d", rec1.Code, http.StatusOK)
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, path, nil)
	req2.RemoteAddr = "203.0.113.10:12345"
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second status: got %d want %d", rec2.Code, http.StatusOK)
	}

	var out1 struct {
		Nonce string `json:"nonce"`
	}
	var out2 struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(rec1.Body.Bytes(), &out1); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &out2); err != nil {
		t.Fatalf("decode second: %v", err)
	}

	if out1.Nonce != "1" || out2.Nonce != "1" {
		t.Fatalf("expected cached nonce 1/1, got %s/%s", out1.Nonce, out2.Nonce)
	}
	if nonceCalls.Load() != 1 {
		t.Fatalf("nonce calls: got %d want 1", nonceCalls.Load())
	}
}

func TestHandler_DepositMemo_CacheExpires(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 11, 10, 0, 0, 0, time.UTC)
	var nonceCalls atomic.Uint64
	h, err := NewHandler(Config{
		BaseChainID:         8453,
		BridgeAddress:       common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
		OWalletUA:           "u1example",
		RefundWindowSeconds: 86400,
		MemoCacheTTL:        2 * time.Second,
		Now: func() time.Time {
			return now
		},
		NonceFn: func() (uint64, error) {
			return nonceCalls.Add(1), nil
		},
	}, &stubDepositReader{}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	path := "/v1/deposit-memo?baseRecipient=0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1"

	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, path, nil)
	req1.RemoteAddr = "203.0.113.11:12345"
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first status: got %d want %d", rec1.Code, http.StatusOK)
	}

	now = now.Add(3 * time.Second)

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, path, nil)
	req2.RemoteAddr = "203.0.113.11:12345"
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second status: got %d want %d", rec2.Code, http.StatusOK)
	}

	var out1 struct {
		Nonce string `json:"nonce"`
	}
	var out2 struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(rec1.Body.Bytes(), &out1); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &out2); err != nil {
		t.Fatalf("decode second: %v", err)
	}

	if out1.Nonce != "1" || out2.Nonce != "2" {
		t.Fatalf("expected nonces 1 then 2 after ttl, got %s/%s", out1.Nonce, out2.Nonce)
	}
	if nonceCalls.Load() != 2 {
		t.Fatalf("nonce calls: got %d want 2", nonceCalls.Load())
	}
}

func TestHandler_RateLimitPerIP(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 11, 10, 0, 0, 0, time.UTC)
	h, err := NewHandler(Config{
		BaseChainID:             8453,
		BridgeAddress:           common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
		OWalletUA:               "u1example",
		RefundWindowSeconds:     86400,
		RateLimitPerIPPerSecond: 1,
		RateLimitBurst:          1,
		Now: func() time.Time {
			return now
		},
		NonceFn: func() (uint64, error) {
			return 1, nil
		},
	}, &stubDepositReader{}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req1 := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	req1.RemoteAddr = "198.51.100.7:4321"
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first status: got %d want %d", rec1.Code, http.StatusOK)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	req2.RemoteAddr = "198.51.100.7:4321"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second status: got %d want %d body=%s", rec2.Code, http.StatusTooManyRequests, rec2.Body.String())
	}

	var out map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode rate-limit response: %v", err)
	}
	if out["error"] != "rate_limited" {
		t.Fatalf("unexpected rate-limit error: %v", out)
	}

	// Different IP should still be allowed at the same instant.
	req3 := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	req3.RemoteAddr = "198.51.100.8:4321"
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("third status (different ip): got %d want %d", rec3.Code, http.StatusOK)
	}

	// Advance one second and the original IP should recover one token.
	now = now.Add(1 * time.Second)
	req4 := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	req4.RemoteAddr = "198.51.100.7:4321"
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusOK {
		t.Fatalf("fourth status after refill: got %d want %d", rec4.Code, http.StatusOK)
	}

	if v := rec4.Header().Get("X-RateLimit-Limit"); v != strconv.Itoa(1) {
		t.Fatalf("unexpected X-RateLimit-Limit: %q", v)
	}
}

func TestHandler_DepositSubmit(t *testing.T) {
	t.Parallel()

	actionSvc := &stubActionService{
		depositResp: depositevent.Payload{
			Version:   "deposits.event.v1",
			DepositID: "0x" + strings.Repeat("11", 32),
			Amount:    100000,
		},
	}
	h, err := NewHandler(Config{
		BaseChainID:         8453,
		BridgeAddress:       common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
		OWalletUA:           "u1example",
		RefundWindowSeconds: 86400,
		NonceFn: func() (uint64, error) {
			return 1, nil
		},
		ActionService: actionSvc,
	}, &stubDepositReader{}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	reqBody := map[string]any{
		"baseRecipient":    "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1",
		"amount":           "100000",
		"nonce":            "7",
		"proofWitnessItem": "0x0102",
	}
	raw, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/v1/deposits/submit", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if actionSvc.depositReq.Amount != 100000 {
		t.Fatalf("deposit amount: got=%d", actionSvc.depositReq.Amount)
	}
	if actionSvc.depositReq.Nonce != 7 {
		t.Fatalf("deposit nonce: got=%d", actionSvc.depositReq.Nonce)
	}
	if !strings.EqualFold(actionSvc.depositReq.BaseRecipient.Hex(), "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1") {
		t.Fatalf("base recipient: got=%s", actionSvc.depositReq.BaseRecipient.Hex())
	}
	var out struct {
		Queued    bool   `json:"queued"`
		DepositID string `json:"depositId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Queued {
		t.Fatalf("expected queued=true")
	}
	if out.DepositID == "" {
		t.Fatalf("expected deposit id")
	}
}

func TestHandler_DepositSubmit_InvalidPayload(t *testing.T) {
	t.Parallel()

	h, err := NewHandler(Config{
		BaseChainID:         8453,
		BridgeAddress:       common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
		OWalletUA:           "u1example",
		RefundWindowSeconds: 86400,
		NonceFn: func() (uint64, error) {
			return 1, nil
		},
		ActionService: &stubActionService{},
	}, &stubDepositReader{}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/deposits/submit", strings.NewReader(`{"baseRecipient":"0x1","amount":"x","nonce":"1","proofWitnessItem":"0x00"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func testConfig() Config {
	return Config{
		BaseChainID:         8453,
		BridgeAddress:       common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
		OWalletUA:           "u1example",
		RefundWindowSeconds: 86400,
		NonceFn: func() (uint64, error) {
			return 1, nil
		},
	}
}

func TestListDeposits_ByBaseRecipient(t *testing.T) {
	t.Parallel()

	var did [32]byte
	did[0] = 0xAA
	var rec20 [20]byte
	rec20[0] = 0xBB

	cfg := testConfig()
	cfg.DepositLister = &stubDepositLister{
		jobs: []deposit.Job{
			{Deposit: deposit.Deposit{DepositID: did, Amount: 5000, BaseRecipient: rec20}, State: deposit.StateConfirmed},
		},
		total: 1,
	}
	h, err := NewHandler(cfg, &stubDepositReader{}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/deposits?baseRecipient=0xBB00000000000000000000000000000000000000&limit=10&offset=0", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var out struct {
		Version string `json:"version"`
		Total   int    `json:"total"`
		Data    []struct {
			DepositID string `json:"depositId"`
			State     string `json:"state"`
			Amount    string `json:"amount"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Version != "v1" || out.Total != 1 || len(out.Data) != 1 {
		t.Fatalf("bad response: %+v", out)
	}
	if out.Data[0].Amount != "5000" || out.Data[0].State != "confirmed" {
		t.Fatalf("bad deposit entry: %+v", out.Data[0])
	}
}

func TestListDeposits_ByTxHash(t *testing.T) {
	t.Parallel()

	var did [32]byte
	did[0] = 0xCC
	var txh [32]byte
	txh[0] = 0xDD

	cfg := testConfig()
	cfg.DepositLister = &stubDepositLister{
		job: &deposit.Job{
			Deposit: deposit.Deposit{DepositID: did, Amount: 9999},
			State:   deposit.StateFinalized,
			TxHash:  txh,
		},
	}
	h, err := NewHandler(cfg, &stubDepositReader{}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/deposits?txHash=0x"+hex.EncodeToString(txh[:]), nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var out struct {
		Total int `json:"total"`
		Data  []struct {
			DepositID string `json:"depositId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Total != 1 || len(out.Data) != 1 {
		t.Fatalf("expected 1 result: %+v", out)
	}
}

func TestListDeposits_NoFilter(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.DepositLister = &stubDepositLister{}
	h, err := NewHandler(cfg, &stubDepositReader{}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/deposits", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want %d", w.Code, http.StatusBadRequest)
	}
}

func TestListDeposits_ListerNil(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	// DepositLister intentionally nil
	h, err := NewHandler(cfg, &stubDepositReader{}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/deposits?baseRecipient=0xBB00000000000000000000000000000000000000", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status: got %d want %d", w.Code, http.StatusNotImplemented)
	}
}

func TestListWithdrawals_ByRequester(t *testing.T) {
	t.Parallel()

	var wid [32]byte
	wid[0] = 0xEE

	cfg := testConfig()
	cfg.WithdrawalLister = &stubWithdrawalLister{
		statuses: []WithdrawalStatus{
			{
				Withdrawal: withdraw.Withdrawal{ID: wid, Amount: 2000, FeeBps: 50, Requester: [20]byte{0x11}},
			},
		},
		total: 1,
	}
	h, err := NewHandler(cfg, &stubDepositReader{}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/withdrawals?requester=0x1100000000000000000000000000000000000000", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var out struct {
		Total int `json:"total"`
		Data  []struct {
			WithdrawalID string `json:"withdrawalId"`
			Amount       string `json:"amount"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Total != 1 || len(out.Data) != 1 || out.Data[0].Amount != "2000" {
		t.Fatalf("bad response: %+v", out)
	}
}

func TestListWithdrawals_ByJunoTxId(t *testing.T) {
	t.Parallel()

	var wid [32]byte
	wid[0] = 0xFF

	cfg := testConfig()
	cfg.WithdrawalLister = &stubWithdrawalLister{
		statuses: []WithdrawalStatus{
			{
				Withdrawal: withdraw.Withdrawal{ID: wid, Amount: 3000},
				JunoTxID:   "abc123",
			},
		},
		total: 1,
	}
	h, err := NewHandler(cfg, &stubDepositReader{}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/withdrawals?junoTxId=abc123", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var out struct {
		Data []struct {
			JunoTxID string `json:"junoTxId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Data) != 1 || out.Data[0].JunoTxID != "abc123" {
		t.Fatalf("bad response: %+v", out)
	}
}

func TestListWithdrawals_ByBaseTxHash(t *testing.T) {
	t.Parallel()

	var wid [32]byte
	wid[0] = 0xAA

	cfg := testConfig()
	cfg.WithdrawalLister = &stubWithdrawalLister{
		statuses: []WithdrawalStatus{
			{
				Withdrawal: withdraw.Withdrawal{ID: wid, Amount: 4000},
				BaseTxHash: "0xdeadbeef",
			},
		},
		total: 1,
	}
	h, err := NewHandler(cfg, &stubDepositReader{}, &stubWithdrawalReader{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/withdrawals?baseTxHash=0xdeadbeef", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var out struct {
		Data []struct {
			BaseTxHash string `json:"baseTxHash"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Data) != 1 || out.Data[0].BaseTxHash != "0xdeadbeef" {
		t.Fatalf("bad response: %+v", out)
	}
}
