package sp1network

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestExecClient_RequestorBalanceWei(t *testing.T) {
	t.Parallel()

	client, err := NewExecClient(ExecClientConfig{
		Binary:           "sp1-prover-adapter",
		MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("NewExecClient: %v", err)
	}
	client.execCommand = func(_ context.Context, _ string, _ []byte) ([]byte, []byte, error) {
		return []byte(`{"version":"sp1.balance.response.v1","balance_wei":"42000"}`), nil, nil
	}

	balance, err := client.RequestorBalanceWei(
		context.Background(),
		common.HexToAddress("0x000000000000000000000000000000000000beef"),
	)
	if err != nil {
		t.Fatalf("RequestorBalanceWei: %v", err)
	}
	if got, want := balance.String(), "42000"; got != want {
		t.Fatalf("balance: got %s want %s", got, want)
	}
}

func TestExecClient_RequestorBalanceWeiRejectsWrongVersion(t *testing.T) {
	t.Parallel()

	client, err := NewExecClient(ExecClientConfig{
		Binary:           "sp1-prover-adapter",
		MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("NewExecClient: %v", err)
	}
	client.execCommand = func(_ context.Context, _ string, _ []byte) ([]byte, []byte, error) {
		return []byte(`{"version":"unexpected","balance_wei":"1"}`), nil, nil
	}
	_, err = client.RequestorBalanceWei(
		context.Background(),
		common.HexToAddress("0x000000000000000000000000000000000000beef"),
	)
	if err == nil {
		t.Fatalf("expected version error")
	}
}

func TestClassifyProveError(t *testing.T) {
	t.Parallel()

	code, retryable, message := ClassifyProveError(NewPermanentError("sp1_invalid_input", errors.New("bad input")))
	if code != "sp1_invalid_input" || retryable {
		t.Fatalf("unexpected classification: code=%s retryable=%v", code, retryable)
	}
	if message == "" {
		t.Fatalf("expected message")
	}

	code, retryable, _ = ClassifyProveError(errors.New("upstream timeout"))
	if code != "sp1_prove_error" || !retryable {
		t.Fatalf("unexpected fallback classification: code=%s retryable=%v", code, retryable)
	}
}
