package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/juno-intents/intents-juno/internal/eth"
)

type stubSender struct {
	gotReq eth.TxRequest
	res    eth.SendResult
	err    error
}

func (s *stubSender) SendAndWaitMined(_ context.Context, req eth.TxRequest) (eth.SendResult, error) {
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

	sender := &stubSender{
		res: eth.SendResult{
			From:    common.HexToAddress("0x0000000000000000000000000000000000000002"),
			Nonce:   7,
			TxHash:  common.HexToHash("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			Receipt: &types.Receipt{Status: types.ReceiptStatusSuccessful},
		},
	}
	h := NewHandler(sender, Config{AuthToken: "secret", MaxBodyBytes: 1024, MaxWaitSeconds: 60})

	body := map[string]any{
		"to":        wantTo.Hex(),
		"data":      "0x0102",
		"value_wei": "123",
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
	if len(sender.gotReq.Data) != 2 || sender.gotReq.Data[0] != 0x01 || sender.gotReq.Data[1] != 0x02 {
		t.Fatalf("Data: got %x", sender.gotReq.Data)
	}
	if sender.gotReq.Value == nil || sender.gotReq.Value.String() != "123" {
		t.Fatalf("Value: got %v", sender.gotReq.Value)
	}
	if sender.gotReq.GasLimit != 55555 {
		t.Fatalf("GasLimit: got %d want %d", sender.gotReq.GasLimit, 55555)
	}
}
