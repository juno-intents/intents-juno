package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/juno-intents/intents-juno/internal/eth"
)

type stubSender struct {
	gotReq eth.TxRequest
	res    eth.SendResult
	err    error
	calls  int
}

func (s *stubSender) SendAndWaitMined(_ context.Context, req eth.TxRequest) (eth.SendResult, error) {
	s.calls++
	s.gotReq = req
	return s.res, s.err
}

func TestHandler_RequiresBearerTokenWhenConfigured(t *testing.T) {
	sender := &stubSender{}
	h := NewHandler(sender, Config{AuthToken: "secret", MaxBodyBytes: 1024, MaxWaitSeconds: 60})

	req := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewBufferString(`{"to":"0x0000000000000000000000000000000000000001"}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandler_SendParsesRequestAndReturnsResult(t *testing.T) {
	wantTo := common.HexToAddress("0x0000000000000000000000000000000000000001")
	wantSelector := []byte{0x53, 0xa5, 0x8a, 0x48}

	sender := &stubSender{
		res: eth.SendResult{
			From:    common.HexToAddress("0x0000000000000000000000000000000000000002"),
			Nonce:   7,
			TxHash:  common.HexToHash("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			Receipt: &types.Receipt{Status: types.ReceiptStatusSuccessful},
		},
	}
	h := NewHandler(sender, Config{AuthToken: "secret", MaxBodyBytes: 1024, MaxWaitSeconds: 60})
	h = NewHandler(sender, Config{
		AuthToken:        "secret",
		MaxBodyBytes:     1024,
		MaxWaitSeconds:   60,
		AllowedContracts: []common.Address{wantTo},
		AllowedSelectors: [][]byte{wantSelector},
	})

	body := map[string]any{
		"to":        wantTo.Hex(),
		"data":      "0x53a58a480102",
		"gas_limit": 55555,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}

	if sender.gotReq.To != wantTo {
		t.Fatalf("To: got %s want %s", sender.gotReq.To, wantTo)
	}
	if len(sender.gotReq.Data) != 6 || sender.gotReq.Data[0] != 0x53 || sender.gotReq.Data[1] != 0xa5 || sender.gotReq.Data[4] != 0x01 || sender.gotReq.Data[5] != 0x02 {
		t.Fatalf("Data: got %x", sender.gotReq.Data)
	}
	if sender.gotReq.Value == nil || sender.gotReq.Value.String() != "0" {
		t.Fatalf("Value: got %v", sender.gotReq.Value)
	}
	if sender.gotReq.GasLimit != 55555 {
		t.Fatalf("GasLimit: got %d want %d", sender.gotReq.GasLimit, 55555)
	}
}

func TestHandler_RejectsSendWhenSelectorIsNotAllowed(t *testing.T) {
	t.Parallel()

	sender := &stubSender{}
	h := NewHandler(sender, Config{
		AuthToken:        "secret",
		MaxBodyBytes:     1024,
		MaxWaitSeconds:   60,
		AllowedContracts: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000001")},
		AllowedSelectors: [][]byte{{0x53, 0xa5, 0x8a, 0x48}},
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewBufferString(`{"to":"0x0000000000000000000000000000000000000001","data":"0x01020304"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want %d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
	}
	if sender.calls != 0 {
		t.Fatalf("sender called: got %d want 0", sender.calls)
	}
}

func TestHandler_RejectsSendWhenSelectorAllowlistIsMissing(t *testing.T) {
	t.Parallel()

	sender := &stubSender{}
	h := NewHandler(sender, Config{
		AuthToken:        "secret",
		MaxBodyBytes:     1024,
		MaxWaitSeconds:   60,
		AllowedContracts: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000001")},
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewBufferString(`{"to":"0x0000000000000000000000000000000000000001","data":"0x53a58a48"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want %d body=%s", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
	}
	if sender.calls != 0 {
		t.Fatalf("sender called: got %d want 0", sender.calls)
	}
}

func TestHandler_RejectsNonZeroValue(t *testing.T) {
	t.Parallel()

	sender := &stubSender{}
	h := NewHandler(sender, Config{
		AuthToken:        "secret",
		MaxBodyBytes:     1024,
		MaxWaitSeconds:   60,
		AllowedContracts: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000001")},
		AllowedSelectors: [][]byte{{0x53, 0xa5, 0x8a, 0x48}},
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewBufferString(`{"to":"0x0000000000000000000000000000000000000001","data":"0x53a58a48","value_wei":"1"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want %d body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
	if sender.calls != 0 {
		t.Fatalf("sender called: got %d want 0", sender.calls)
	}
}

func TestHandler_ProbeAliases(t *testing.T) {
	t.Parallel()

	h := NewHandler(&stubSender{}, Config{})
	for _, path := range []string{"/healthz", "/livez", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status: got %d want %d body=%s", path, rr.Code, http.StatusOK, rr.Body.String())
		}
	}
}

func TestHandler_ProbePathsRemainUnauthenticated(t *testing.T) {
	t.Parallel()

	sender := &stubSender{}
	h := NewHandler(sender, Config{AuthToken: "secret", MaxBodyBytes: 1024, MaxWaitSeconds: 60})

	for _, path := range []string{"/livez", "/readyz", "/healthz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("%s status: got %d want %d", path, rr.Code, http.StatusOK)
		}
	}
}

func TestHandler_ReadyzReturnsServiceUnavailableWhenReadinessFails(t *testing.T) {
	t.Parallel()

	h := NewHandler(&stubSender{}, Config{
		AuthToken: "secret",
		ReadinessCheck: func(context.Context) error {
			return errors.New("relayer underfunded")
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want %d body=%s", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("relayer underfunded")) {
		t.Fatalf("body missing readiness error: %s", rr.Body.String())
	}
}

func TestHandler_RejectsSendOutsideAllowlist(t *testing.T) {
	t.Parallel()

	sender := &stubSender{}
	h := NewHandler(sender, Config{
		AuthToken:        "secret",
		MaxBodyBytes:     1024,
		MaxWaitSeconds:   60,
		AllowedContracts: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000002")},
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewBufferString(`{"to":"0x0000000000000000000000000000000000000001"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want %d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
	}
	if sender.calls != 0 {
		t.Fatalf("sender called: got %d want 0", sender.calls)
	}
}

func TestHandler_RejectsSendWhenAllowlistIsMissing(t *testing.T) {
	t.Parallel()

	sender := &stubSender{}
	h := NewHandler(sender, Config{
		AuthToken:      "secret",
		MaxBodyBytes:   1024,
		MaxWaitSeconds: 60,
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewBufferString(`{"to":"0x0000000000000000000000000000000000000001"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want %d body=%s", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
	}
	if sender.calls != 0 {
		t.Fatalf("sender called: got %d want 0", sender.calls)
	}
}

func TestHandler_RejectsSendWhenContractAllowlistIsEmpty(t *testing.T) {
	t.Parallel()

	sender := &stubSender{}
	h := NewHandler(sender, Config{
		AuthToken:        "secret",
		MaxBodyBytes:     1024,
		MaxWaitSeconds:   60,
		AllowedSelectors: [][]byte{{0x53, 0xa5, 0x8a, 0x48}},
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewBufferString(`{"to":"0x0000000000000000000000000000000000000001","data":"0x53a58a48"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want %d body=%s", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
	}
	if sender.calls != 0 {
		t.Fatalf("sender called: got %d want 0", sender.calls)
	}
}

func TestHandler_IdempotencyKey_ReplaysOriginalResultWithoutResend(t *testing.T) {
	t.Parallel()

	sender := &stubSender{
		res: eth.SendResult{
			From:   common.HexToAddress("0x0000000000000000000000000000000000000002"),
			Nonce:  9,
			TxHash: common.HexToHash("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			Receipt: &types.Receipt{
				Status: types.ReceiptStatusSuccessful,
			},
		},
	}
	now := time.Unix(1_700_000_000, 0)
	h := NewHandler(sender, Config{
		AuthToken:          "secret",
		MaxBodyBytes:       1024,
		MaxWaitSeconds:     60,
		IdempotencyTTL:     time.Minute,
		IdempotencyMaxKeys: 8,
		AllowedContracts:   []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000001")},
		AllowedSelectors:   [][]byte{{0x53, 0xa5, 0x8a, 0x48}},
		Now: func() time.Time {
			return now
		},
	})

	body := []byte(`{"to":"0x0000000000000000000000000000000000000001","data":"0x53a58a48","gas_limit":21000}`)
	req1 := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewReader(body))
	req1.Header.Set("Authorization", "Bearer secret")
	req1.Header.Set("Idempotency-Key", "abc123")
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)

	req2 := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer secret")
	req2.Header.Set("Idempotency-Key", "abc123")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)

	if rr1.Code != http.StatusOK || rr2.Code != http.StatusOK {
		t.Fatalf("statuses: got %d and %d want 200", rr1.Code, rr2.Code)
	}
	if rr1.Body.String() != rr2.Body.String() {
		t.Fatalf("replayed body mismatch: %s != %s", rr1.Body.String(), rr2.Body.String())
	}
	if sender.calls != 1 {
		t.Fatalf("sender calls: got %d want 1", sender.calls)
	}
}

func TestHandler_RateLimitsByTokenAndFallsBackToRemoteAddr(t *testing.T) {
	t.Parallel()

	sender := &stubSender{
		err: errors.New("boom"),
	}
	now := time.Unix(1_700_000_000, 0)
	hToken := NewHandler(sender, Config{
		AuthToken:                  "secret",
		MaxBodyBytes:               1024,
		MaxWaitSeconds:             60,
		AllowedContracts:           []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000001")},
		AllowedSelectors:           [][]byte{{0x53, 0xa5, 0x8a, 0x48}},
		RateLimitPerSecond:         1,
		RateLimitBurst:             1,
		RateLimitMaxTrackedClients: 4,
		Now: func() time.Time {
			return now
		},
	})

	body := []byte(`{"to":"0x0000000000000000000000000000000000000001","data":"0x53a58a48"}`)
	req1 := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewReader(body))
	req1.Header.Set("Authorization", "Bearer secret")
	req1.RemoteAddr = "203.0.113.9:1234"
	rr1 := httptest.NewRecorder()
	hToken.ServeHTTP(rr1, req1)

	req2 := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer secret")
	req2.RemoteAddr = "198.51.100.7:5555"
	rr2 := httptest.NewRecorder()
	hToken.ServeHTTP(rr2, req2)

	if rr1.Code != http.StatusInternalServerError {
		t.Fatalf("first status: got %d want %d", rr1.Code, http.StatusInternalServerError)
	}
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second status: got %d want %d body=%s", rr2.Code, http.StatusTooManyRequests, rr2.Body.String())
	}

	hIP := NewHandler(sender, Config{
		MaxBodyBytes:               1024,
		MaxWaitSeconds:             60,
		AllowedContracts:           []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000001")},
		AllowedSelectors:           [][]byte{{0x53, 0xa5, 0x8a, 0x48}},
		RateLimitPerSecond:         1,
		RateLimitBurst:             1,
		RateLimitMaxTrackedClients: 4,
		Now: func() time.Time {
			return now
		},
	})

	now = now.Add(time.Second)
	req3 := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewReader(body))
	req3.RemoteAddr = "203.0.113.10:3333"
	rr3 := httptest.NewRecorder()
	hIP.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusInternalServerError {
		t.Fatalf("ip fallback status: got %d want %d", rr3.Code, http.StatusInternalServerError)
	}

	req4 := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewReader(body))
	req4.RemoteAddr = "203.0.113.10:4444"
	rr4 := httptest.NewRecorder()
	hIP.ServeHTTP(rr4, req4)
	if rr4.Code != http.StatusTooManyRequests {
		t.Fatalf("ip fallback throttled status: got %d want %d body=%s", rr4.Code, http.StatusTooManyRequests, rr4.Body.String())
	}
}

func TestClientKey_UsesAuthPrincipalInsteadOfTokenMaterial(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewReader([]byte("{}")))
	req.RemoteAddr = "203.0.113.9:1234"

	if got, want := clientKey(req, "backoffice-admin"), "principal:backoffice-admin"; got != want {
		t.Fatalf("clientKey: got %q want %q", got, want)
	}
}
