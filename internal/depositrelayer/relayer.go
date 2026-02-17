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
	"github.com/juno-intents/intents-juno/internal/deposit"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/idempotency"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/proofclient"
	"github.com/juno-intents/intents-juno/internal/proverinput"
)

var (
	ErrInvalidConfig     = errors.New("depositrelayer: invalid config")
	ErrInvalidEvent      = errors.New("depositrelayer: invalid event")
	ErrInvalidCheckpoint = errors.New("depositrelayer: invalid checkpoint")
)

type Sender interface {
	Send(ctx context.Context, req httpapi.SendRequest) (httpapi.SendResponse, error)
}

type Config struct {
	BaseChainID    uint32
	BridgeAddress  common.Address
	DepositImageID common.Hash
	// Optional 64-byte OWallet IVK. When set, relayer requires per-deposit
	// witness items and builds binary guest input for real deposit proofs.
	OWalletIVKBytes []byte

	OperatorAddresses []common.Address
	OperatorThreshold int

	MaxItems  int
	MaxAge    time.Duration
	DedupeMax int
	Owner     string
	ClaimTTL  time.Duration

	GasLimit uint64

	ProofRequestTimeout time.Duration
	ProofPriority       int

	Now func() time.Time
}

type DepositEvent struct {
	Commitment common.Hash
	LeafIndex  uint64
	Amount     uint64
	Memo       []byte
	// Optional per-deposit witness payload. Layout must match
	// proverinput.DepositWitnessItemLen.
	ProofWitnessItem []byte
}

type CheckpointPackage struct {
	Checkpoint         checkpoint.Checkpoint
	OperatorSignatures [][]byte
}

type Relayer struct {
	cfg Config

	log    *slog.Logger
	store  deposit.Store
	sender Sender
	prover proofclient.Client

	expectedBridgeMemo [20]byte

	batcher *batching.Batcher[mintBatchItem]
	staged  map[common.Hash]struct{}

	quorumVerifier *checkpoint.QuorumVerifier

	checkpoint *checkpoint.Checkpoint
	opSigs     [][]byte
}

type mintBatchItem struct {
	Mint             bridgeabi.MintItem
	ProofWitnessItem []byte
}

func New(cfg Config, store deposit.Store, sender Sender, prover proofclient.Client, log *slog.Logger) (*Relayer, error) {
	if cfg.BaseChainID == 0 {
		return nil, fmt.Errorf("%w: BaseChainID must be non-zero", ErrInvalidConfig)
	}
	if (cfg.BridgeAddress == common.Address{}) {
		return nil, fmt.Errorf("%w: BridgeAddress must be non-zero", ErrInvalidConfig)
	}
	if cfg.MaxItems <= 0 {
		return nil, fmt.Errorf("%w: MaxItems must be > 0", ErrInvalidConfig)
	}
	if len(cfg.OperatorAddresses) == 0 {
		return nil, fmt.Errorf("%w: OperatorAddresses must be non-empty", ErrInvalidConfig)
	}
	if cfg.OperatorThreshold <= 0 {
		return nil, fmt.Errorf("%w: OperatorThreshold must be > 0", ErrInvalidConfig)
	}
	if cfg.MaxAge <= 0 {
		return nil, fmt.Errorf("%w: MaxAge must be > 0", ErrInvalidConfig)
	}
	if cfg.DedupeMax <= 0 {
		return nil, fmt.Errorf("%w: DedupeMax must be > 0", ErrInvalidConfig)
	}
	if cfg.Owner == "" {
		cfg.Owner = fmt.Sprintf("deposit-relayer-%d", time.Now().UnixNano())
	}
	if cfg.ClaimTTL <= 0 {
		cfg.ClaimTTL = 30 * time.Second
	}
	if cfg.ProofRequestTimeout <= 0 {
		cfg.ProofRequestTimeout = 15 * time.Minute
	}
	if cfg.ProofPriority < 0 {
		return nil, fmt.Errorf("%w: ProofPriority must be >= 0", ErrInvalidConfig)
	}
	if n := len(cfg.OWalletIVKBytes); n != 0 && n != 64 {
		return nil, fmt.Errorf("%w: OWalletIVKBytes must be 64 bytes when set", ErrInvalidConfig)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if store == nil || sender == nil || prover == nil {
		return nil, fmt.Errorf("%w: nil store/sender/prover", ErrInvalidConfig)
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	b, err := batching.New[mintBatchItem](batching.Config{
		MaxItems: cfg.MaxItems,
		MaxAge:   cfg.MaxAge,
		Now:      cfg.Now,
	})
	if err != nil {
		return nil, err
	}

	quorumVerifier, err := checkpoint.NewQuorumVerifier(cfg.OperatorAddresses, cfg.OperatorThreshold)
	if err != nil {
		return nil, err
	}

	var bridge20 [20]byte
	copy(bridge20[:], cfg.BridgeAddress[:])

	return &Relayer{
		cfg:                cfg,
		log:                log,
		store:              store,
		sender:             sender,
		prover:             prover,
		expectedBridgeMemo: bridge20,
		batcher:            b,
		staged:             make(map[common.Hash]struct{}, cfg.MaxItems*2),
		quorumVerifier:     quorumVerifier,
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
	if _, err := r.quorumVerifier.VerifyCheckpointSignatures(cp, pkg.OperatorSignatures); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCheckpoint, err)
	}

	// Only move forward in height to avoid accidental reorg/rollback usage.
	if r.checkpoint != nil && cp.Height <= r.checkpoint.Height {
		return nil
	}

	r.checkpoint = &cp
	r.opSigs = pkg.OperatorSignatures

	r.log.Info("updated checkpoint", "height", cp.Height, "digest", checkpoint.Digest(cp))
	return r.FlushDue(ctx)
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
	job, _, err := r.store.UpsertConfirmed(ctx, deposit.Deposit{
		DepositID:        idBytes,
		Commitment:       [32]byte(ev.Commitment),
		LeafIndex:        ev.LeafIndex,
		Amount:           ev.Amount,
		BaseRecipient:    [20]byte(recipient),
		ProofWitnessItem: append([]byte(nil), ev.ProofWitnessItem...),
	})
	if err != nil {
		return err
	}
	if job.State != deposit.StateConfirmed {
		return nil
	}
	return r.refillFromStore(ctx)
}

func (r *Relayer) FlushDue(ctx context.Context) error {
	if r.checkpoint == nil || len(r.opSigs) == 0 {
		return nil
	}
	if err := r.refillFromStore(ctx); err != nil {
		return err
	}
	batch, ok := r.batcher.FlushDue()
	if !ok {
		return nil
	}
	if err := r.submitBatch(ctx, *r.checkpoint, r.opSigs, batch); err != nil {
		r.unstageBatch(batch)
		return err
	}
	r.unstageBatch(batch)
	return nil
}

func (r *Relayer) Flush(ctx context.Context) error {
	if r.checkpoint == nil || len(r.opSigs) == 0 {
		return nil
	}
	if err := r.refillFromStore(ctx); err != nil {
		return err
	}
	batch, ok := r.batcher.Flush()
	if !ok {
		return nil
	}
	if err := r.submitBatch(ctx, *r.checkpoint, r.opSigs, batch); err != nil {
		r.unstageBatch(batch)
		return err
	}
	r.unstageBatch(batch)
	return nil
}

func (r *Relayer) refillFromStore(ctx context.Context) error {
	if r.checkpoint == nil || len(r.opSigs) == 0 {
		return nil
	}

	limit := r.cfg.MaxItems * 4
	if limit < r.cfg.MaxItems {
		limit = r.cfg.MaxItems
	}
	jobs, err := r.store.ClaimConfirmed(ctx, r.cfg.Owner, r.cfg.ClaimTTL, limit)
	if err != nil {
		return err
	}

	for _, job := range jobs {
		id := common.Hash(job.Deposit.DepositID)
		if _, ok := r.staged[id]; ok {
			continue
		}
		item := bridgeabi.MintItem{
			DepositId: id,
			Recipient: common.Address(job.Deposit.BaseRecipient),
			Amount:    new(big.Int).SetUint64(job.Deposit.Amount),
		}
		r.staged[id] = struct{}{}
		batch, ok := r.batcher.Add(job.Deposit.DepositID, mintBatchItem{
			Mint:             item,
			ProofWitnessItem: append([]byte(nil), job.Deposit.ProofWitnessItem...),
		})
		if !ok {
			continue
		}
		if err := r.submitBatch(ctx, *r.checkpoint, r.opSigs, batch); err != nil {
			r.unstageBatch(batch)
			return err
		}
		r.unstageBatch(batch)
	}
	return nil
}

func (r *Relayer) submitBatch(ctx context.Context, cp checkpoint.Checkpoint, opSigs [][]byte, batch batching.Batch[mintBatchItem]) error {
	if len(batch.Items) == 0 {
		return nil
	}

	items := make([]bridgeabi.MintItem, 0, len(batch.Items))
	witnessItems := make([][]byte, 0, len(batch.Items))
	for _, it := range batch.Items {
		items = append(items, it.Val.Mint)
		witnessItems = append(witnessItems, it.Val.ProofWitnessItem)
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

	privateInput, err := r.encodePrivateInput(cp, opSigs, items, witnessItems)
	if err != nil {
		return err
	}

	depositIDs := make([]common.Hash, 0, len(batch.Items))
	for _, it := range batch.Items {
		depositIDs = append(depositIDs, common.Hash(it.ID))
	}
	batchID := idempotency.DepositBatchIDV1(depositIDs)
	jobID := idempotency.ProofJobIDV1("deposit", batchID, r.cfg.DepositImageID, journal, privateInput)

	pctx, cancel := context.WithTimeout(ctx, r.cfg.ProofRequestTimeout)
	defer cancel()

	proofRes, err := r.prover.RequestProof(pctx, proofclient.Request{
		JobID:        jobID,
		Pipeline:     "deposit",
		ImageID:      r.cfg.DepositImageID,
		Journal:      journal,
		PrivateInput: privateInput,
		Deadline:     r.cfg.Now().Add(r.cfg.ProofRequestTimeout),
		Priority:     r.cfg.ProofPriority,
	})
	if err != nil {
		return err
	}
	seal := proofRes.Seal
	if len(seal) == 0 {
		return fmt.Errorf("depositrelayer: empty proof seal from proof requester")
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

	finalizeIDs := make([][32]byte, 0, len(batch.Items))
	for _, it := range batch.Items {
		finalizeIDs = append(finalizeIDs, it.ID)
	}
	if err := r.store.MarkBatchSubmitted(ctx, finalizeIDs, cp, seal); err != nil {
		return fmt.Errorf("depositrelayer: mark batch submitted: %w", err)
	}

	res, err := r.sender.Send(ctx, req)
	if err != nil {
		return err
	}
	if res.Receipt == nil {
		return fmt.Errorf("depositrelayer: base-relayer did not return a receipt")
	}
	if res.Receipt.Status != 1 {
		return fmt.Errorf("depositrelayer: mintBatch tx reverted")
	}

	txHash := common.HexToHash(res.TxHash)
	if err := r.store.FinalizeBatch(ctx, finalizeIDs, cp, seal, [32]byte(txHash)); err != nil {
		return fmt.Errorf("depositrelayer: finalize batch: %w", err)
	}

	r.log.Info("submitted mintBatch",
		"checkpointHeight", cp.Height,
		"items", len(items),
		"txHash", res.TxHash,
	)
	return nil
}

func (r *Relayer) unstageBatch(batch batching.Batch[mintBatchItem]) {
	for _, item := range batch.Items {
		delete(r.staged, common.Hash(item.ID))
	}
}

func (r *Relayer) encodePrivateInput(cp checkpoint.Checkpoint, opSigs [][]byte, items []bridgeabi.MintItem, witnessItems [][]byte) ([]byte, error) {
	if len(r.cfg.OWalletIVKBytes) == 64 {
		var ivk [64]byte
		copy(ivk[:], r.cfg.OWalletIVKBytes)
		for i, w := range witnessItems {
			if len(w) == 0 {
				return nil, fmt.Errorf("depositrelayer: missing proof witness item for batch index %d", i)
			}
		}
		return proverinput.EncodeDepositGuestPrivateInput(cp, ivk, witnessItems)
	}
	return proverinput.EncodeDepositPrivateInputV1(cp, opSigs, items)
}
