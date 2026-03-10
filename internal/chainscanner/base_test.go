package chainscanner

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// mockEthClient is a test double for EthClient.
type mockEthClient struct {
	blockNumber    uint64
	blockNumberErr error
	logs           []types.Log
	filterLogsErr  error
	filterCalls    []ethereum.FilterQuery
	headers        map[uint64]*types.Header
	headerErr      error
}

func (m *mockEthClient) BlockNumber(_ context.Context) (uint64, error) {
	return m.blockNumber, m.blockNumberErr
}

func (m *mockEthClient) FilterLogs(_ context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	m.filterCalls = append(m.filterCalls, q)
	return m.logs, m.filterLogsErr
}

func (m *mockEthClient) HeaderByNumber(_ context.Context, number *big.Int) (*types.Header, error) {
	if m.headerErr != nil {
		return nil, m.headerErr
	}
	if number == nil {
		return nil, errors.New("nil header number")
	}
	if m.headers == nil {
		m.headers = make(map[uint64]*types.Header)
	}
	height := number.Uint64()
	hdr, ok := m.headers[height]
	if !ok {
		var parent common.Hash
		if height > 0 {
			prev, err := m.HeaderByNumber(context.Background(), new(big.Int).SetUint64(height-1))
			if err != nil {
				return nil, err
			}
			parent = prev.Hash()
		}
		hdr = &types.Header{
			Number:     new(big.Int).SetUint64(height),
			ParentHash: parent,
			Extra:      common.LeftPadBytes(new(big.Int).SetUint64(height).Bytes(), 8),
		}
		m.headers[height] = hdr
	}
	return hdr, nil
}

func TestNewBaseScanner_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     BaseScannerConfig
		wantErr bool
	}{
		{
			name:    "nil client",
			cfg:     BaseScannerConfig{Client: nil, BridgeAddr: common.HexToAddress("0x1234"), StateStore: NewMemoryStateStore()},
			wantErr: true,
		},
		{
			name:    "empty bridge address",
			cfg:     BaseScannerConfig{Client: &mockEthClient{}, BridgeAddr: common.Address{}, StateStore: NewMemoryStateStore()},
			wantErr: true,
		},
		{
			name:    "nil state store",
			cfg:     BaseScannerConfig{Client: &mockEthClient{}, BridgeAddr: common.HexToAddress("0x1234"), StateStore: nil},
			wantErr: true,
		},
		{
			name: "valid config",
			cfg: BaseScannerConfig{
				Client:     &mockEthClient{},
				BridgeAddr: common.HexToAddress("0x1234"),
				StateStore: NewMemoryStateStore(),
			},
			wantErr: false,
		},
		{
			name: "defaults applied",
			cfg: BaseScannerConfig{
				Client:     &mockEthClient{},
				BridgeAddr: common.HexToAddress("0x1234"),
				StateStore: NewMemoryStateStore(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			scanner, err := NewBaseScanner(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewBaseScanner: %v", err)
			}
			if scanner == nil {
				t.Fatal("expected non-nil scanner")
			}
		})
	}
}

func TestBaseScanner_PollNoNewBlocks(t *testing.T) {
	t.Parallel()

	stateStore := NewMemoryStateStore()
	ctx := context.Background()
	_ = stateStore.SetLastHeight(ctx, "test-scanner", 100)

	client := &mockEthClient{blockNumber: 100}
	scanner, err := NewBaseScanner(BaseScannerConfig{
		Client:      client,
		BridgeAddr:  common.HexToAddress("0x1234"),
		StateStore:  stateStore,
		ServiceName: "test-scanner",
	})
	if err != nil {
		t.Fatalf("NewBaseScanner: %v", err)
	}

	var published []WithdrawRequestedEvent
	err = scanner.poll(ctx, 0, func(_ context.Context, e WithdrawRequestedEvent) error {
		published = append(published, e)
		return nil
	})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(published) != 0 {
		t.Fatalf("expected no events, got %d", len(published))
	}
}

// buildWithdrawRequestedLog creates a synthetic WithdrawRequested log for testing.
func buildWithdrawRequestedLog(
	bridgeAddr common.Address,
	withdrawalID [32]byte,
	requester common.Address,
	amount *big.Int,
	recipientUA []byte,
	expiry uint64,
	feeBps uint64,
	blockNumber uint64,
	txHash common.Hash,
	logIndex uint,
) types.Log {
	topic0 := crypto.Keccak256Hash([]byte("WithdrawRequested(bytes32,address,uint256,bytes,uint64,uint96)"))

	// ABI-encode the data: amount, offset(recipientUA), expiry, feeBps, len(recipientUA), recipientUA
	amountPadded := common.LeftPadBytes(amount.Bytes(), 32)
	offsetPadded := common.LeftPadBytes(big.NewInt(128).Bytes(), 32) // 4*32 = 128
	expiryPadded := common.LeftPadBytes(new(big.Int).SetUint64(expiry).Bytes(), 32)
	feeBpsPadded := common.LeftPadBytes(new(big.Int).SetUint64(feeBps).Bytes(), 32)
	lenPadded := common.LeftPadBytes(big.NewInt(int64(len(recipientUA))).Bytes(), 32)

	// Pad recipientUA to 32-byte boundary.
	paddedUA := make([]byte, ((len(recipientUA)+31)/32)*32)
	copy(paddedUA, recipientUA)

	data := make([]byte, 0, 160+len(paddedUA))
	data = append(data, amountPadded...)
	data = append(data, offsetPadded...)
	data = append(data, expiryPadded...)
	data = append(data, feeBpsPadded...)
	data = append(data, lenPadded...)
	data = append(data, paddedUA...)

	return types.Log{
		Address:     bridgeAddr,
		Topics:      []common.Hash{topic0, common.BytesToHash(withdrawalID[:]), common.BytesToHash(requester.Bytes())},
		Data:        data,
		BlockNumber: blockNumber,
		TxHash:      txHash,
		Index:       logIndex,
	}
}

func TestBaseScanner_PollParsesEvents(t *testing.T) {
	t.Parallel()

	bridgeAddr := common.HexToAddress("0xBBBB")
	stateStore := NewMemoryStateStore()
	ctx := context.Background()

	wid := [32]byte{0x01}
	requester := common.HexToAddress("0xAAAA")
	amount := big.NewInt(5000)
	recipientUA := []byte("juno1recipient")
	expiry := uint64(1700000000)
	feeBps := uint64(100)
	txHash := common.HexToHash("0xdeadbeef")

	log := buildWithdrawRequestedLog(bridgeAddr, wid, requester, amount, recipientUA, expiry, feeBps, 50, txHash, 0)

	client := &mockEthClient{
		blockNumber: 100,
		logs:        []types.Log{log},
	}

	scanner, err := NewBaseScanner(BaseScannerConfig{
		Client:           client,
		BridgeAddr:       bridgeAddr,
		StateStore:       stateStore,
		ServiceName:      "test-scanner",
		MaxBlocksPerPoll: 1000,
	})
	if err != nil {
		t.Fatalf("NewBaseScanner: %v", err)
	}

	var published []WithdrawRequestedEvent
	err = scanner.poll(ctx, 1, func(_ context.Context, e WithdrawRequestedEvent) error {
		published = append(published, e)
		return nil
	})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(published) != 1 {
		t.Fatalf("expected 1 event, got %d", len(published))
	}

	ev := published[0]
	if ev.WithdrawalID != wid {
		t.Fatalf("withdrawal id mismatch")
	}
	if ev.Requester != requester {
		t.Fatalf("requester mismatch")
	}
	if ev.Amount.Cmp(amount) != 0 {
		t.Fatalf("amount: got=%s want=%s", ev.Amount, amount)
	}
	if string(ev.RecipientUA) != string(recipientUA) {
		t.Fatalf("recipientUA mismatch: got=%q want=%q", ev.RecipientUA, recipientUA)
	}
	if ev.Expiry != expiry {
		t.Fatalf("expiry: got=%d want=%d", ev.Expiry, expiry)
	}
	if ev.FeeBps != feeBps {
		t.Fatalf("feeBps: got=%d want=%d", ev.FeeBps, feeBps)
	}
	if ev.BlockNumber != 50 {
		t.Fatalf("blockNumber: got=%d want=50", ev.BlockNumber)
	}
	if ev.TxHash != txHash {
		t.Fatalf("txHash mismatch")
	}

	// State should be updated.
	height, err := stateStore.GetLastHeight(ctx, "test-scanner")
	if err != nil {
		t.Fatalf("GetLastHeight: %v", err)
	}
	if height != 100 {
		t.Fatalf("last height: got=%d want=100", height)
	}
}

func TestBaseScanner_PollChunking(t *testing.T) {
	t.Parallel()

	stateStore := NewMemoryStateStore()
	ctx := context.Background()

	client := &mockEthClient{blockNumber: 250}

	scanner, err := NewBaseScanner(BaseScannerConfig{
		Client:           client,
		BridgeAddr:       common.HexToAddress("0x1234"),
		StateStore:       stateStore,
		ServiceName:      "test-scanner",
		MaxBlocksPerPoll: 100,
	})
	if err != nil {
		t.Fatalf("NewBaseScanner: %v", err)
	}

	publish := func(_ context.Context, _ WithdrawRequestedEvent) error { return nil }

	// First poll: 1..100
	if err := scanner.poll(ctx, 1, publish); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	h, _ := stateStore.GetLastHeight(ctx, "test-scanner")
	if h != 100 {
		t.Fatalf("after poll 1: got=%d want=100", h)
	}
	if len(client.filterCalls) != 1 {
		t.Fatalf("filter calls: got=%d want=1", len(client.filterCalls))
	}
	if client.filterCalls[0].FromBlock.Int64() != 1 || client.filterCalls[0].ToBlock.Int64() != 100 {
		t.Fatalf("filter range: from=%d to=%d", client.filterCalls[0].FromBlock.Int64(), client.filterCalls[0].ToBlock.Int64())
	}

	// Second poll: 101..200
	client.filterCalls = nil
	if err := scanner.poll(ctx, 1, publish); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	h, _ = stateStore.GetLastHeight(ctx, "test-scanner")
	if h != 200 {
		t.Fatalf("after poll 2: got=%d want=200", h)
	}

	// Third poll: 201..250
	client.filterCalls = nil
	if err := scanner.poll(ctx, 1, publish); err != nil {
		t.Fatalf("poll 3: %v", err)
	}
	h, _ = stateStore.GetLastHeight(ctx, "test-scanner")
	if h != 250 {
		t.Fatalf("after poll 3: got=%d want=250", h)
	}
}

func TestBaseScanner_PublishErrorStopsProcessing(t *testing.T) {
	t.Parallel()

	bridgeAddr := common.HexToAddress("0xBBBB")
	stateStore := NewMemoryStateStore()
	ctx := context.Background()

	log1 := buildWithdrawRequestedLog(bridgeAddr, [32]byte{1}, common.HexToAddress("0xAAAA"), big.NewInt(100), []byte("ua"), 1000, 50, 10, common.Hash{}, 0)
	log2 := buildWithdrawRequestedLog(bridgeAddr, [32]byte{2}, common.HexToAddress("0xAAAA"), big.NewInt(200), []byte("ua"), 2000, 50, 11, common.Hash{}, 1)

	client := &mockEthClient{
		blockNumber: 20,
		logs:        []types.Log{log1, log2},
	}

	scanner, err := NewBaseScanner(BaseScannerConfig{
		Client:      client,
		BridgeAddr:  bridgeAddr,
		StateStore:  stateStore,
		ServiceName: "test-scanner",
	})
	if err != nil {
		t.Fatalf("NewBaseScanner: %v", err)
	}

	publishErr := errors.New("publish failed")
	callCount := 0
	err = scanner.poll(ctx, 1, func(_ context.Context, _ WithdrawRequestedEvent) error {
		callCount++
		if callCount == 2 {
			return publishErr
		}
		return nil
	})
	if !errors.Is(err, publishErr) {
		t.Fatalf("expected publish error, got %v", err)
	}
	if callCount != 2 {
		t.Fatalf("expected publish called twice, got %d", callCount)
	}

	// State should NOT be updated since publish failed.
	h, _ := stateStore.GetLastHeight(ctx, "test-scanner")
	if h != 0 {
		t.Fatalf("expected state not updated, got height=%d", h)
	}
}

func TestBaseScanner_RunCancellation(t *testing.T) {
	t.Parallel()

	client := &mockEthClient{blockNumber: 0}
	stateStore := NewMemoryStateStore()

	scanner, err := NewBaseScanner(BaseScannerConfig{
		Client:       client,
		BridgeAddr:   common.HexToAddress("0x1234"),
		StateStore:   stateStore,
		ServiceName:  "test-scanner",
		PollInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewBaseScanner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- scanner.Run(ctx, 0, func(_ context.Context, _ WithdrawRequestedEvent) error {
			return nil
		})
	}()

	// Let it run a few polls.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestBaseScanner_ResumesFromState(t *testing.T) {
	t.Parallel()

	stateStore := NewMemoryStateStore()
	ctx := context.Background()
	_ = stateStore.SetLastHeight(ctx, "test-scanner", 500)

	client := &mockEthClient{blockNumber: 510}
	scanner, err := NewBaseScanner(BaseScannerConfig{
		Client:           client,
		BridgeAddr:       common.HexToAddress("0x1234"),
		StateStore:       stateStore,
		ServiceName:      "test-scanner",
		MaxBlocksPerPoll: 1000,
	})
	if err != nil {
		t.Fatalf("NewBaseScanner: %v", err)
	}

	if err := scanner.poll(ctx, 0, func(_ context.Context, _ WithdrawRequestedEvent) error { return nil }); err != nil {
		t.Fatalf("poll: %v", err)
	}

	if len(client.filterCalls) != 1 {
		t.Fatalf("expected 1 filter call, got %d", len(client.filterCalls))
	}
	from := client.filterCalls[0].FromBlock.Int64()
	to := client.filterCalls[0].ToBlock.Int64()
	if from != 501 || to != 510 {
		t.Fatalf("filter range: from=%d to=%d, want from=501 to=510", from, to)
	}
}

func TestParseWithdrawRequestedLog_InvalidTopics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		log  types.Log
	}{
		{
			name: "too few topics",
			log:  types.Log{Topics: []common.Hash{withdrawRequestedTopic0}},
		},
		{
			name: "wrong topic0",
			log:  types.Log{Topics: []common.Hash{{0x01}, {0x02}, {0x03}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseWithdrawRequestedLog(tt.log)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseWithdrawRequestedLog_DataTooShort(t *testing.T) {
	t.Parallel()

	lg := types.Log{
		Topics: []common.Hash{withdrawRequestedTopic0, {0x01}, {0x02}},
		Data:   make([]byte, 100), // less than 160
	}
	_, err := parseWithdrawRequestedLog(lg)
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestBaseScanner_StartBlockUsedWhenNoState(t *testing.T) {
	t.Parallel()

	stateStore := NewMemoryStateStore()
	ctx := context.Background()

	client := &mockEthClient{blockNumber: 200}
	scanner, err := NewBaseScanner(BaseScannerConfig{
		Client:           client,
		BridgeAddr:       common.HexToAddress("0x1234"),
		StateStore:       stateStore,
		ServiceName:      "test-scanner",
		MaxBlocksPerPoll: 1000,
	})
	if err != nil {
		t.Fatalf("NewBaseScanner: %v", err)
	}

	if err := scanner.poll(ctx, 150, func(_ context.Context, _ WithdrawRequestedEvent) error { return nil }); err != nil {
		t.Fatalf("poll: %v", err)
	}

	if len(client.filterCalls) != 1 {
		t.Fatalf("expected 1 filter call, got %d", len(client.filterCalls))
	}
	from := client.filterCalls[0].FromBlock.Int64()
	if from != 150 {
		t.Fatalf("expected from=150 (startBlock), got %d", from)
	}
}

func TestBaseScanner_RewindsOnStoredHashMismatch(t *testing.T) {
	t.Parallel()

	makeHeader := func(number uint64, parent common.Hash, extra byte) *types.Header {
		return &types.Header{
			Number:     new(big.Int).SetUint64(number),
			ParentHash: parent,
			Extra:      []byte{extra},
		}
	}

	stateStore := NewMemoryStateStore()
	ctx := context.Background()

	header10 := makeHeader(10, common.HexToHash("0x10"), 0x10)
	old11 := makeHeader(11, header10.Hash(), 0x11)
	new11 := makeHeader(11, header10.Hash(), 0x21)
	new12 := makeHeader(12, new11.Hash(), 0x22)

	if err := stateStore.StoreBlockRef(ctx, "test-scanner", BlockRef{
		Height:     10,
		Hash:       header10.Hash(),
		ParentHash: header10.ParentHash,
	}); err != nil {
		t.Fatalf("StoreBlockRef(10): %v", err)
	}
	if err := stateStore.StoreBlockRef(ctx, "test-scanner", BlockRef{
		Height:     11,
		Hash:       old11.Hash(),
		ParentHash: old11.ParentHash,
	}); err != nil {
		t.Fatalf("StoreBlockRef(11): %v", err)
	}
	if err := stateStore.SetLastHeight(ctx, "test-scanner", 11); err != nil {
		t.Fatalf("SetLastHeight: %v", err)
	}

	client := &mockEthClient{
		blockNumber: 12,
		headers: map[uint64]*types.Header{
			10: header10,
			11: new11,
			12: new12,
		},
	}
	scanner, err := NewBaseScanner(BaseScannerConfig{
		Client:           client,
		BridgeAddr:       common.HexToAddress("0x1234"),
		StateStore:       stateStore,
		ServiceName:      "test-scanner",
		MaxBlocksPerPoll: 100,
	})
	if err != nil {
		t.Fatalf("NewBaseScanner: %v", err)
	}

	if err := scanner.poll(ctx, 1, func(_ context.Context, _ WithdrawRequestedEvent) error { return nil }); err != nil {
		t.Fatalf("poll: %v", err)
	}

	if len(client.filterCalls) != 1 {
		t.Fatalf("expected 1 filter call, got %d", len(client.filterCalls))
	}
	if got := client.filterCalls[0].FromBlock.Int64(); got != 11 {
		t.Fatalf("filter from block: got=%d want=11", got)
	}
	if got := client.filterCalls[0].ToBlock.Int64(); got != 12 {
		t.Fatalf("filter to block: got=%d want=12", got)
	}

	if got, err := stateStore.GetLastHeight(ctx, "test-scanner"); err != nil {
		t.Fatalf("GetLastHeight: %v", err)
	} else if got != 12 {
		t.Fatalf("last height: got=%d want=12", got)
	}

	if ref, ok, err := stateStore.GetBlockRef(ctx, "test-scanner", 11); err != nil {
		t.Fatalf("GetBlockRef(11): %v", err)
	} else if !ok || ref.Hash != new11.Hash() {
		t.Fatalf("block 11 not rewound to replacement hash")
	}
	if ref, ok, err := stateStore.GetBlockRef(ctx, "test-scanner", 12); err != nil {
		t.Fatalf("GetBlockRef(12): %v", err)
	} else if !ok || ref.Hash != new12.Hash() {
		t.Fatalf("block 12 not stored after rewind")
	}
}
