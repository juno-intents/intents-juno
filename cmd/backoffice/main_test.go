package main

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/backoffice"
)

type stubChainIDReader struct {
	calls int
	err   error
}

func (s *stubChainIDReader) ChainID(context.Context) (*big.Int, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return big.NewInt(8453), nil
}

func TestChainReadinessCheck(t *testing.T) {
	t.Parallel()

	reader := &stubChainIDReader{}
	check := chainReadinessCheck(reader)
	if err := check(context.Background()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if reader.calls != 1 {
		t.Fatalf("calls: got %d want 1", reader.calls)
	}
}

func TestChainReadinessCheck_PropagatesFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("base rpc down")
	check := chainReadinessCheck(&stubChainIDReader{err: wantErr})
	if err := check(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("error: got %v want %v", err, wantErr)
	}
}

func TestServiceEntryURLs(t *testing.T) {
	t.Parallel()

	urls := serviceEntryURLs([]backoffice.ServiceEntry{
		{Label: "bridge", URL: " https://bridge.example/healthz "},
		{Label: "empty", URL: "   "},
		{Label: "backoffice", URL: "https://backoffice.example/healthz"},
	})
	if len(urls) != 2 {
		t.Fatalf("len(urls) = %d, want 2", len(urls))
	}
	if urls[0] != "https://bridge.example/healthz" {
		t.Fatalf("urls[0] = %q", urls[0])
	}
	if urls[1] != "https://backoffice.example/healthz" {
		t.Fatalf("urls[1] = %q", urls[1])
	}
}

func TestBackofficeAlertEngineConfigUsesServiceURLsAndThresholds(t *testing.T) {
	t.Parallel()

	operatorGasMinWei := big.NewInt(123)
	proverFundsMinWei := big.NewInt(456)
	operatorAddress := common.HexToAddress("0x0000000000000000000000000000000000000abc")
	baseRelayerSignerAddress := common.HexToAddress("0x0000000000000000000000000000000000000fed")
	sp1Requestor := common.HexToAddress("0x0000000000000000000000000000000000000def")

	cfg := backofficeAlertEngineConfig(
		nil,
		nil,
		[]common.Address{operatorAddress},
		[]common.Address{baseRelayerSignerAddress},
		sp1Requestor,
		[]backoffice.ServiceEntry{{Label: "bridge", URL: "https://bridge.example/healthz"}},
		45*time.Second,
		240,
		operatorGasMinWei,
		proverFundsMinWei,
	)

	if cfg.CheckInterval != 45*time.Second {
		t.Fatalf("CheckInterval = %s, want 45s", cfg.CheckInterval)
	}
	if len(cfg.ServiceURLs) != 1 || cfg.ServiceURLs[0] != "https://bridge.example/healthz" {
		t.Fatalf("ServiceURLs = %#v", cfg.ServiceURLs)
	}
	if len(cfg.OperatorAddresses) != 1 || cfg.OperatorAddresses[0] != operatorAddress {
		t.Fatalf("OperatorAddresses = %#v", cfg.OperatorAddresses)
	}
	if len(cfg.BaseRelayerSignerAddresses) != 1 || cfg.BaseRelayerSignerAddresses[0] != baseRelayerSignerAddress {
		t.Fatalf("BaseRelayerSignerAddresses = %#v", cfg.BaseRelayerSignerAddresses)
	}
	if cfg.SP1RequestorAddress != sp1Requestor {
		t.Fatalf("SP1RequestorAddress = %s", cfg.SP1RequestorAddress.Hex())
	}
	if cfg.StuckBatchMinutes != 240 {
		t.Fatalf("StuckBatchMinutes = %d, want 240", cfg.StuckBatchMinutes)
	}
	if cfg.OperatorGasMinWei != operatorGasMinWei {
		t.Fatalf("OperatorGasMinWei pointer mismatch")
	}
	if cfg.ProverFundsMinWei != proverFundsMinWei {
		t.Fatalf("ProverFundsMinWei pointer mismatch")
	}
}
