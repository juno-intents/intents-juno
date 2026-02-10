package depositrelayer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/juno-intents/intents-juno/internal/batching"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/idempotency"
	"github.com/juno-intents/intents-juno/internal/memo"
)

var (
	ErrInvalidConfig    = errors.New("depositrelayer: invalid config")
	ErrInvalidEvent     = errors.New("depositrelayer: invalid event")
	ErrInvalidCheckpoint = errors.New("depositrelayer: invalid checkpoint")
)

type Sender interface {
	Send(ctx context.Context, req httpapi.SendRequest) (httpapi.SendResponse, error)
}

type Prover interface {
	Prove(ctx context.Context, imageID common.Hash, journal []byte) ([]byte, error)
}

type Config struct {
	BaseChainID    uint32
	BridgeAddress  common.Address
	DepositImageID common.Hash

	MaxItems  int
	MaxAge    time.Duration
	DedupeMax int

	GasLimit uint64

	Now func() time.Time
}

type DepositEvent struct {
	Commitment common.Hash
	LeafIndex  uint64
	Amount     uint64
	Memo       []byte
}

type CheckpointPackage struct {
	Checkpoint         checkpoint.Checkpoint
	OperatorSignatures [][]byte
}

type Relayer struct {
	cfg Config

	log    *slog.Logger
	sender Sender
	prover Prover

	expectedBridgeMemo [20]byte

	batcher *batching.Batcher[bridgeabi.MintItem]

	seen      map[common.Hash]struct{}
	seenOrder []common.Hash

	checkpoint *checkpoint.Checkpoint
	opSigs     [][]byte

	queue []batching.Batch[bridgeabi.MintItem]
}

func New(cfg Config, sender Sender, prover Prover, log *slog.Logger) (*Relayer, error) {
	if cfg.BaseChainID == 0 {
		return nil, fmt.Errorf("%w: BaseChainID must be non-zero", ErrInvalidConfig)
	}
	if (cfg.BridgeAddress == common.Address{}) {
		return nil, fmt.Errorf("%w: BridgeAddress must be non-zero", ErrInvalidConfig)
	}
	if cfg.MaxItems <= 0 {
		return nil, fmt.Errorf("%w: MaxItems must be > 0", ErrInvalidConfig)
	}
	if cfg.MaxAge <= 0 {
		return nil, fmt.Errorf("%w: MaxAge must be > 0", ErrInvalidConfig)
	}
	if cfg.DedupeMax <= 0 {
		return nil, fmt.Errorf("%w: DedupeMax must be > 0", ErrInvalidConfig)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if sender == nil || prover == nil {
		return nil, fmt.Errorf("%w: nil sender/prover", ErrInvalidConfig)
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	b, err := batching.New[bridgeabi.MintItem](batching.Config{
		MaxItems: cfg.MaxItems,
		MaxAge:   cfg.MaxAge,
		Now:      cfg.Now,
	})
	if err != nil {
		return nil, err
	}

	var bridge20 [20]byte
	copy(bridge20[:], cfg.BridgeAddress[:])

	return &Relayer{
		cfg:               cfg,
		log:               log,
		sender:            sender,
		prover:            prover,
		expectedBridgeMemo: bridge20,
		batcher:           b,
		seen:              make(map[common.Hash]struct{}, cfg.DedupeMax),
	}, nil
}

func (r *Relayer) IngestCheckpoint(ctx context.Context, pkg CheckpointPackage) error {
	cp := pkg.Checkpoint
	if cp.BaseChainID != uint64(r.cfg.BaseChainID) {
		return fmt.Errorf("%w: baseChainID mismatch: want %d got %d", ErrInvalidCheckpoint, r.cfg.BaseChainID, cp.BaseChainID)
	}
	if cp.BridgeContract != r.cfg.BridgeAddress {
		return fmt.Errorf("%w: bridge mismatch: want %s got %s", ErrInvalidCheckpoint, r.cfg.BridgeAddress, cp.BridgeContract)
	}
	if len(pkg.OperatorSignatures) == 0 {
		return fmt.Errorf("%w: empty operator signatures", ErrInvalidCheckpoint)
	}

	// Only move forward in height to avoid accidental reorg/rollback usage.
	if r.checkpoint != nil && cp.Height <= r.checkpoint.Height {
		return nil
	}

	r.checkpoint = &cp
	r.opSigs = pkg.OperatorSignatures

	r.log.Info("updated checkpoint", "height", cp.Height, "digest", checkpoint.Digest(cp))
	return r.drain(ctx)
}

func (r *Relayer) IngestDeposit(ctx context.Context, ev DepositEvent) error {
	if ev.Amount == 0 {
		return fmt.Errorf("%w: amount must be > 0", ErrInvalidEvent)
	}
	if len(ev.Memo) != memo.MemoLen {
		return fmt.Errorf("%w: memo must be %d bytes, got %d", ErrInvalidEvent, memo.MemoLen, len(ev.Memo))
	}

	dm, err := memo.ParseDepositMemoV1(ev.Memo, r.cfg.BaseChainID, r.expectedBridgeMemo)
	if err != nil {
		return err
	}

	recipient := common.Address(dm.BaseRecipient)
	if (recipient == common.Address{}) {
		return fmt.Errorf("%w: recipient must be non-zero", ErrInvalidEvent)
	}

	idBytes := idempotency.DepositIDV1([32]byte(ev.Commitment), ev.LeafIndex)
	depositID := common.Hash(idBytes)

	if r.markSeen(depositID) {
		return nil
	}

	item := bridgeabi.MintItem{
		DepositId: depositID,
		Recipient: recipient,
		Amount:    new(big.Int).SetUint64(ev.Amount),
	}

	batch, ok := r.batcher.Add(idBytes, item)
	if ok {
		r.queue = append(r.queue, batch)
		return r.drain(ctx)
	}
	return nil
}

func (r *Relayer) FlushDue(ctx context.Context) error {
	batch, ok := r.batcher.FlushDue()
	if ok {
		r.queue = append(r.queue, batch)
	}
	return r.drain(ctx)
}

func (r *Relayer) Flush(ctx context.Context) error {
	batch, ok := r.batcher.Flush()
	if ok {
		r.queue = append(r.queue, batch)
	}
	return r.drain(ctx)
}

func (r *Relayer) drain(ctx context.Context) error {
	if r.checkpoint == nil || len(r.opSigs) == 0 {
		return nil
	}

	for len(r.queue) > 0 {
		b := r.queue[0]
		r.queue = r.queue[1:]

		if err := r.submitBatch(ctx, *r.checkpoint, r.opSigs, b); err != nil {
			// Push back and stop; we require operator intervention for persistent failures.
			r.queue = append([]batching.Batch[bridgeabi.MintItem]{b}, r.queue...)
			return err
		}
	}
	return nil
}

func (r *Relayer) submitBatch(ctx context.Context, cp checkpoint.Checkpoint, opSigs [][]byte, batch batching.Batch[bridgeabi.MintItem]) error {
	if len(batch.Items) == 0 {
		return nil
	}

	items := make([]bridgeabi.MintItem, 0, len(batch.Items))
	for _, it := range batch.Items {
		items = append(items, it.Val)
	}

	journal, err := bridgeabi.EncodeDepositJournal(bridgeabi.DepositJournal{
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
		Items:            items,
	})
	if err != nil {
		return err
	}

	seal, err := r.prover.Prove(ctx, r.cfg.DepositImageID, journal)
	if err != nil {
		return err
	}

	calldata, err := bridgeabi.PackMintBatchCalldata(cp, opSigs, seal, journal)
	if err != nil {
		return err
	}

	req := httpapi.SendRequest{
		To:       cp.BridgeContract.Hex(),
		Data:     hexutil.Encode(calldata),
		GasLimit: r.cfg.GasLimit,
	}

	res, err := r.sender.Send(ctx, req)
	if err != nil {
		return err
	}

	r.log.Info("submitted mintBatch",
		"checkpointHeight", cp.Height,
		"items", len(items),
		"txHash", res.TxHash,
	)
	return nil
}

// markSeen returns true if the deposit has already been observed.
func (r *Relayer) markSeen(id common.Hash) bool {
	if _, ok := r.seen[id]; ok {
		return true
	}
	r.seen[id] = struct{}{}
	r.seenOrder = append(r.seenOrder, id)
	if len(r.seenOrder) > r.cfg.DedupeMax {
		old := r.seenOrder[0]
		r.seenOrder = r.seenOrder[1:]
		delete(r.seen, old)
	}
	return false
}

