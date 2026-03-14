package bridgeconfig

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
)

type stubBridgeCaller struct {
	minDepositAmount uint64
	minDepositAdmin  common.Address
	err              error
}

func (s *stubBridgeCaller) CallContract(_ context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	minDepositData, err := bridgeabi.PackMinDepositAmountCalldata()
	if err != nil {
		return nil, err
	}
	minDepositAdminData, err := bridgeabi.PackMinDepositAdminCalldata()
	if err != nil {
		return nil, err
	}
	switch {
	case string(msg.Data) == string(minDepositData):
		return common.LeftPadBytes(new(big.Int).SetUint64(s.minDepositAmount).Bytes(), 32), nil
	case string(msg.Data) == string(minDepositAdminData):
		return common.LeftPadBytes(s.minDepositAdmin.Bytes(), 32), nil
	default:
		return nil, errors.New("unexpected calldata")
	}
}

func TestReaderLoadReadsMinDepositAmountAndAdmin(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC)
	reader, err := NewReader(&stubBridgeCaller{
		minDepositAmount: 201005025,
		minDepositAdmin:  common.HexToAddress("0x0000000000000000000000000000000000000abc"),
	}, common.HexToAddress("0x0000000000000000000000000000000000000123"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	reader.now = func() time.Time { return now }

	snapshot, err := reader.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if snapshot.MinDepositAmount != 201005025 {
		t.Fatalf("MinDepositAmount = %d, want 201005025", snapshot.MinDepositAmount)
	}
	if snapshot.MinDepositAdmin != common.HexToAddress("0x0000000000000000000000000000000000000abc") {
		t.Fatalf("MinDepositAdmin = %s", snapshot.MinDepositAdmin.Hex())
	}
	if !snapshot.LoadedAt.Equal(now) {
		t.Fatalf("LoadedAt = %s, want %s", snapshot.LoadedAt, now)
	}
}

func TestCacheKeepsLastKnownSnapshotOnRefreshFailure(t *testing.T) {
	t.Parallel()

	loader := &stubBridgeLoader{
		snapshot: Snapshot{
			MinDepositAmount: 201005025,
			MinDepositAdmin:  common.HexToAddress("0x0000000000000000000000000000000000000abc"),
		},
	}
	cache, err := NewCache(loader, time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	cache.refresh(context.Background())
	loader.err = errors.New("rpc down")
	cache.refresh(context.Background())

	snapshot, err := cache.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if snapshot.MinDepositAmount != 201005025 {
		t.Fatalf("MinDepositAmount = %d, want 201005025", snapshot.MinDepositAmount)
	}
}

type stubBridgeLoader struct {
	snapshot Snapshot
	err      error
}

func (s *stubBridgeLoader) Load(context.Context) (Snapshot, error) {
	if s.err != nil {
		return Snapshot{}, s.err
	}
	return s.snapshot, nil
}
