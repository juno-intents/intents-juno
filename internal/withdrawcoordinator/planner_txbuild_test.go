package withdrawcoordinator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

func TestTxBuildPlanner_Plan_BuildsOutputsAndParsesPlan(t *testing.T) {
	t.Parallel()

	cfg := TxBuildPlannerConfig{
		Binary:           "juno-txbuild",
		WalletID:         "wallet-1",
		ChangeAddress:    "j1change",
		BaseChainID:      8453,
		BridgeAddress:    common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
		MinConfirmations: 1,
		ExpiryOffset:     40,
		FeeMultiplier:    1,
	}
	p, err := NewTxBuildPlanner(cfg)
	if err != nil {
		t.Fatalf("NewTxBuildPlanner: %v", err)
	}

	batchID := seq32ForPlanner(0x80)
	w0 := withdraw.Withdrawal{
		ID:          seq32ForPlanner(0x20),
		Amount:      10_000,
		FeeBps:      50,
		RecipientUA: []byte("j1recipient-a"),
		Expiry:      time.Date(2026, 2, 11, 0, 0, 0, 0, time.UTC).Add(24 * time.Hour),
	}
	w1 := withdraw.Withdrawal{
		ID:          seq32ForPlanner(0x00),
		Amount:      5_000,
		FeeBps:      0,
		RecipientUA: []byte("j1recipient-b"),
		Expiry:      time.Date(2026, 2, 11, 0, 0, 0, 0, time.UTC).Add(24 * time.Hour),
	}

	p.execCommand = func(_ context.Context, name string, args []string, env []string) ([]byte, error) {
		if name != "juno-txbuild" {
			t.Fatalf("binary: got %q want %q", name, "juno-txbuild")
		}
		if !slices.Contains(args, "send-many") {
			t.Fatalf("missing send-many arg: %v", args)
		}
		if !slices.Contains(args, "--json") {
			t.Fatalf("missing --json arg: %v", args)
		}
		// Ensure planner passes RPC URL through env for txbuild.
		foundRPC := false
		for _, v := range env {
			if v == "JUNO_RPC_URL="+cfg.RPCURL {
				foundRPC = true
			}
		}
		if cfg.RPCURL != "" && !foundRPC {
			t.Fatalf("missing JUNO_RPC_URL in env")
		}

		idx := slices.Index(args, "--outputs-file")
		if idx < 0 || idx+1 >= len(args) {
			t.Fatalf("missing --outputs-file in args: %v", args)
		}
		raw, err := os.ReadFile(args[idx+1])
		if err != nil {
			t.Fatalf("read outputs file: %v", err)
		}
		var outs []txbuildOutput
		if err := json.Unmarshal(raw, &outs); err != nil {
			t.Fatalf("decode outputs file: %v", err)
		}
		if len(outs) != 2 {
			t.Fatalf("outputs len: got %d want %d", len(outs), 2)
		}

		// Outputs are sorted by withdrawal ID ascending.
		if outs[0].ToAddress != "j1recipient-b" || outs[1].ToAddress != "j1recipient-a" {
			t.Fatalf("unexpected output order: %+v", outs)
		}
		// net(10000,50bps)=9950
		if outs[0].AmountZat != "5000" || outs[1].AmountZat != "9950" {
			t.Fatalf("unexpected output amounts: %+v", outs)
		}

		b0, err := hex.DecodeString(outs[0].MemoHex)
		if err != nil {
			t.Fatalf("decode memo hex: %v", err)
		}
		m0, err := memo.ParseWithdrawalMemoV1(b0, cfg.BaseChainID, to20(cfg.BridgeAddress))
		if err != nil {
			t.Fatalf("parse memo: %v", err)
		}
		if m0.WithdrawalID != w1.ID || m0.BatchID != batchID {
			t.Fatalf("memo domain ids mismatch")
		}

		return []byte(`{"version":"v1","status":"ok","data":{"version":"v0","kind":"send-many"}}`), nil
	}

	gotPlan, err := p.Plan(context.Background(), batchID, []withdraw.Withdrawal{w0, w1})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	var plan map[string]any
	if err := json.Unmarshal(gotPlan, &plan); err != nil {
		t.Fatalf("decode plan: %v", err)
	}
	if plan["version"] != "v0" {
		t.Fatalf("plan version: got %v want v0", plan["version"])
	}
	if plan["kind"] != "send-many" {
		t.Fatalf("plan kind: got %v want send-many", plan["kind"])
	}
}

func TestTxBuildPlanner_Plan_RejectsInvalidRecipientUA(t *testing.T) {
	t.Parallel()

	cfg := TxBuildPlannerConfig{
		Binary:           "juno-txbuild",
		WalletID:         "wallet-1",
		ChangeAddress:    "j1change",
		BaseChainID:      8453,
		BridgeAddress:    common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
		MinConfirmations: 1,
		ExpiryOffset:     40,
		FeeMultiplier:    1,
	}
	p, err := NewTxBuildPlanner(cfg)
	if err != nil {
		t.Fatalf("NewTxBuildPlanner: %v", err)
	}

	p.execCommand = func(_ context.Context, _ string, _ []string, _ []string) ([]byte, error) {
		t.Fatalf("execCommand should not be called")
		return nil, nil
	}

	w := withdraw.Withdrawal{
		ID:          seq32ForPlanner(0x00),
		Amount:      1,
		FeeBps:      0,
		RecipientUA: []byte{0xff},
		Expiry:      time.Date(2026, 2, 11, 0, 0, 0, 0, time.UTC).Add(24 * time.Hour),
	}
	_, err = p.Plan(context.Background(), seq32ForPlanner(0x80), []withdraw.Withdrawal{w})
	if err == nil || !strings.Contains(err.Error(), "invalid withdrawal recipient UA") {
		t.Fatalf("expected invalid recipient UA error, got %v", err)
	}
}

func TestParseTxBuildJSONEnvelope_HandlesErrorEnvelope(t *testing.T) {
	t.Parallel()

	_, err := parseTxBuildJSONEnvelope([]byte(`{"version":"v1","status":"err","error":{"code":"invalid_request","message":"bad inputs"}}`))
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "invalid_request") {
		t.Fatalf("missing error code in message: %v", err)
	}
}

func TestNewTxBuildPlanner_RejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	_, err := NewTxBuildPlanner(TxBuildPlannerConfig{})
	if !errors.Is(err, ErrInvalidTxBuildPlannerConfig) {
		t.Fatalf("expected ErrInvalidTxBuildPlannerConfig, got %v", err)
	}
}

func seq32ForPlanner(start byte) (out [32]byte) {
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
}

func to20(a common.Address) [20]byte {
	var out [20]byte
	copy(out[:], a[:])
	return out
}
