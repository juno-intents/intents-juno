package boundless

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func TestExecClient_SubmitOffchain(t *testing.T) {
	t.Parallel()

	client, err := NewExecClient(ExecClientConfig{
		Binary:           "boundless-cli",
		MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("NewExecClient: %v", err)
	}
	client.execCommand = func(_ context.Context, _ string, _ []byte) ([]byte, []byte, error) {
		return []byte(`{"version":"boundless.submit.response.v1","request_id":7,"submission_path":"offchain","seal":"0x0102","metadata":{"source":"test"}}`), nil, nil
	}

	resp, err := client.SubmitOffchain(context.Background(), SubmitRequest{
		RequestID:        7,
		ChainID:          8453,
		RequestorAddress: common.HexToAddress("0x000000000000000000000000000000000000beef"),
		MarketAddress:    common.HexToAddress("0x000000000000000000000000000000000000cafe"),
		JobID:            common.HexToHash("0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98"),
		Pipeline:         "deposit",
		ImageID:          common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:          []byte{0x01},
		PrivateInput:     []byte{0x02},
		Deadline:         time.Now().UTC().Add(time.Minute),
		Priority:         1,
	})
	if err != nil {
		t.Fatalf("SubmitOffchain: %v", err)
	}
	if got, want := resp.RequestID, uint64(7); got != want {
		t.Fatalf("requestID: got %d want %d", got, want)
	}
	if got, want := resp.SubmissionPath, "offchain"; got != want {
		t.Fatalf("submission path: got %q want %q", got, want)
	}
	if len(resp.Seal) != 2 || resp.Seal[0] != 0x01 || resp.Seal[1] != 0x02 {
		t.Fatalf("seal mismatch: %x", resp.Seal)
	}
}

func TestExecClient_SubmitErrorClassification(t *testing.T) {
	t.Parallel()

	client, err := NewExecClient(ExecClientConfig{
		Binary:           "boundless-cli",
		MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("NewExecClient: %v", err)
	}
	client.execCommand = func(_ context.Context, _ string, _ []byte) ([]byte, []byte, error) {
		return []byte(`{"version":"boundless.submit.response.v1","error":"insufficient funds","error_code":"insufficient_funds","retryable":false}`), nil, nil
	}
	_, err = client.SubmitOnchain(context.Background(), OnchainSubmitRequest{
		SubmitRequest: SubmitRequest{
			RequestID:        1,
			ChainID:          8453,
			RequestorAddress: common.HexToAddress("0x000000000000000000000000000000000000beef"),
			MarketAddress:    common.HexToAddress("0x000000000000000000000000000000000000cafe"),
			JobID:            common.HexToHash("0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98"),
			Pipeline:         "withdraw",
			ImageID:          common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa02"),
			Journal:          []byte{0x01},
			Deadline:         time.Now().UTC().Add(time.Minute),
		},
		FundingMode: FundingModeMinMaxBalance,
	})
	var subErr *SubmitError
	if !errors.As(err, &subErr) {
		t.Fatalf("expected SubmitError, got %v", err)
	}
	if subErr.Code != "insufficient_funds" || subErr.Retryable {
		t.Fatalf("unexpected submit error fields: %+v", subErr)
	}
}

func TestExecClient_FundingMethods(t *testing.T) {
	t.Parallel()

	client, err := NewExecClient(ExecClientConfig{
		Binary:           "boundless-cli",
		MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("NewExecClient: %v", err)
	}
	responses := [][]byte{
		[]byte(`{"version":"boundless.balance.response.v1","balance_wei":"42"}`),
		[]byte(`{"version":"boundless.topup.response.v1","tx_hash":"0xabc"}`),
	}
	call := 0
	client.execCommand = func(_ context.Context, _ string, _ []byte) ([]byte, []byte, error) {
		out := responses[call]
		call++
		return out, nil, nil
	}

	balance, err := client.RequestorBalanceWei(context.Background(), common.HexToAddress("0x000000000000000000000000000000000000beef"))
	if err != nil {
		t.Fatalf("RequestorBalanceWei: %v", err)
	}
	if balance.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("balance: got %s want 42", balance)
	}

	txHash, err := client.TopUpRequestor(context.Background(), common.HexToAddress("0x000000000000000000000000000000000000beef"), big.NewInt(10))
	if err != nil {
		t.Fatalf("TopUpRequestor: %v", err)
	}
	if txHash != "0xabc" {
		t.Fatalf("tx hash: got %q want %q", txHash, "0xabc")
	}
}
