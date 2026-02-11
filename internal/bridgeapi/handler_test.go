package bridgeapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/deposit"
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
