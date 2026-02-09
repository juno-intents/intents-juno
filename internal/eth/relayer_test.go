package eth

import (
	"context"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	return nil
}

type fakeBackend struct {
	mu sync.Mutex

	pendingNonce uint64
	nonceCalls   int

	suggestTip *big.Int
	baseFee    *big.Int
	gasEst     uint64

	sent []*types.Transaction

	receipts map[common.Hash]*types.Receipt

	sendHook func(tx *types.Transaction) error
}

func (b *fakeBackend) PendingNonceAt(_ context.Context, _ common.Address) (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nonceCalls++
	return b.pendingNonce, nil
}

func (b *fakeBackend) SuggestGasTipCap(_ context.Context) (*big.Int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return new(big.Int).Set(b.suggestTip), nil
}

func (b *fakeBackend) HeaderByNumber(_ context.Context, _ *big.Int) (*types.Header, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return &types.Header{BaseFee: new(big.Int).Set(b.baseFee)}, nil
}

func (b *fakeBackend) EstimateGas(_ context.Context, _ ethereum.CallMsg) (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.gasEst, nil
}

func (b *fakeBackend) SendTransaction(_ context.Context, tx *types.Transaction) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sent = append(b.sent, tx)
	if b.sendHook != nil {
		return b.sendHook(tx)
	}
	return nil
}

func (b *fakeBackend) TransactionReceipt(_ context.Context, h common.Hash) (*types.Receipt, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.receipts == nil {
		b.receipts = make(map[common.Hash]*types.Receipt)
	}
	if r, ok := b.receipts[h]; ok {
		return r, nil
	}
	return nil, ethereum.NotFound
}

func TestRelayer_ReplacesStuckTxByBumpingFees(t *testing.T) {
	ctx := context.Background()

	key, err := crypto.HexToECDSA("4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}
	signer := NewLocalSigner(key)

	clock := &fakeClock{now: time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)}

	backend := &fakeBackend{
		pendingNonce: 0,
		suggestTip:   big.NewInt(2),
		baseFee:      big.NewInt(100),
		gasEst:       50_000,
		receipts:     make(map[common.Hash]*types.Receipt),
	}

	// Mine the second (replacement) tx.
	backend.sendHook = func(tx *types.Transaction) error {
		if len(backend.sent) == 2 {
			backend.receipts[tx.Hash()] = &types.Receipt{
				TxHash:      tx.Hash(),
				Status:      types.ReceiptStatusSuccessful,
				BlockNumber: big.NewInt(1),
			}
		}
		return nil
	}

	r, err := NewRelayer(backend, []Signer{signer}, RelayerConfig{
		ChainID:                big.NewInt(8453),
		GasLimitMultiplier:     1.2,
		MinTipCap:              big.NewInt(1),
		ReplaceAfter:           10 * time.Second,
		ReceiptPollInterval:    5 * time.Second,
		MaxReplacements:        1,
		ReplacementBumpPercent: 10,
		MinReplacementTipBump:  big.NewInt(1),
		MinReplacementFeeBump:  big.NewInt(1),
		Now:                    clock.Now,
		Sleep:                  clock.Sleep,
	})
	if err != nil {
		t.Fatalf("NewRelayer: %v", err)
	}

	to := common.HexToAddress("0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1")
	res, err := r.SendAndWaitMined(ctx, TxRequest{
		To:    to,
		Data:  []byte{0x01, 0x02},
		Value: big.NewInt(0),
	})
	if err != nil {
		t.Fatalf("SendAndWaitMined: %v", err)
	}
	if res.Receipt == nil {
		t.Fatalf("expected receipt")
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	if backend.nonceCalls != 1 {
		t.Fatalf("PendingNonceAt calls: got %d want %d", backend.nonceCalls, 1)
	}
	if len(backend.sent) != 2 {
		t.Fatalf("sent txs: got %d want %d", len(backend.sent), 2)
	}

	tx0 := backend.sent[0]
	tx1 := backend.sent[1]

	if tx0.Nonce() != 0 || tx1.Nonce() != 0 {
		t.Fatalf("nonce mismatch: %d %d", tx0.Nonce(), tx1.Nonce())
	}
	if tx1.GasTipCap().Cmp(tx0.GasTipCap()) <= 0 {
		t.Fatalf("tipCap not bumped: old=%s new=%s", tx0.GasTipCap(), tx1.GasTipCap())
	}
	if tx1.GasFeeCap().Cmp(tx0.GasFeeCap()) <= 0 {
		t.Fatalf("feeCap not bumped: old=%s new=%s", tx0.GasFeeCap(), tx1.GasFeeCap())
	}

	if res.TxHash != tx1.Hash() {
		t.Fatalf("result hash: got %s want %s", res.TxHash, tx1.Hash())
	}
}
