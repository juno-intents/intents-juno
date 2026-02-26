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
	if code != "sp1_request_timeout" || !retryable {
		t.Fatalf("unexpected fallback classification: code=%s retryable=%v", code, retryable)
	}
}

func TestClassifyProveError_Heuristics(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		err       error
		wantCode  string
		wantRetry bool
	}{
		{
			name:      "unexecutable is permanent",
			err:       errors.New("proverexec: sp1 network groth16 prove failed: Proof request 0xabc is unexecutable"),
			wantCode:  "sp1_request_unexecutable",
			wantRetry: false,
		},
		{
			name:      "unfulfillable is retryable",
			err:       errors.New("proverexec: sp1 network groth16 prove failed: Proof request 0xabc is unfulfillable"),
			wantCode:  "sp1_request_unfulfillable",
			wantRetry: true,
		},
		{
			name:      "auction timeout is retryable",
			err:       errors.New("proverexec: sp1 network groth16 prove failed: Proof request 0xabc timed out during the auction"),
			wantCode:  "sp1_request_auction_timeout",
			wantRetry: true,
		},
		{
			name:      "invalid payload is permanent",
			err:       errors.New("proverexec: unsupported image id"),
			wantCode:  "sp1_invalid_input",
			wantRetry: false,
		},
		{
			name:      "simulation failure is permanent",
			err:       errors.New("proverexec: sp1 network groth16 prove failed: Program simulation failed"),
			wantCode:  "sp1_simulation_failed",
			wantRetry: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotCode, gotRetryable, gotMessage := ClassifyProveError(tc.err)
			if gotCode != tc.wantCode || gotRetryable != tc.wantRetry {
				t.Fatalf(
					"classification mismatch code=%s retryable=%v want_code=%s want_retryable=%v",
					gotCode,
					gotRetryable,
					tc.wantCode,
					tc.wantRetry,
				)
			}
			if gotMessage == "" {
				t.Fatalf("expected non-empty message")
			}
		})
	}
}
