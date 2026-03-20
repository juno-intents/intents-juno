package depositrelayer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/bridgeconfig"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/deposit"
	"github.com/juno-intents/intents-juno/internal/dlq"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/idempotency"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/proof"
	"github.com/juno-intents/intents-juno/internal/proofclient"
	"github.com/juno-intents/intents-juno/internal/proverinput"
	"github.com/juno-intents/intents-juno/internal/runtimeconfig"
)

var (
	ErrInvalidConfig          = errors.New("depositrelayer: invalid config")
	ErrInvalidEvent           = errors.New("depositrelayer: invalid event")
	ErrInvalidCheckpoint      = errors.New("depositrelayer: invalid checkpoint")
	ErrProofAttemptsExhausted = errors.New("depositrelayer: proof attempts exhausted")
)

type Sender interface {
	Send(ctx context.Context, req httpapi.SendRequest) (httpapi.SendResponse, error)
}

type ReadinessChecker interface {
	Ready(ctx context.Context) error
}

type DepositWitnessRefresher interface {
	RefreshDepositWitness(ctx context.Context, anchorHeight int64, witnessItem []byte) (common.Hash, []byte, error)
}

type RuntimeSettingsProvider interface {
	Current() (runtimeconfig.Settings, error)
	Ready(ctx context.Context) error
}

type BridgeSettingsProvider interface {
	Current() (bridgeconfig.Snapshot, error)
	Ready(ctx context.Context) error
}

type TipHeightProvider interface {
	TipHeight(ctx context.Context) (int64, error)
}

type ReceiptReader interface {
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
}

type ProofStore interface {
	GetJob(ctx context.Context, jobID common.Hash) (proof.JobRecord, error)
}

type Config struct {
	BaseChainID    uint32
	BridgeAddress  common.Address
	DepositImageID common.Hash
	// 64-byte OWallet IVK used to build binary guest input for real deposit
	// proofs. Missing IVK fails closed.
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

	MaxProofAttempts int // default 3; 0 = unlimited

	// DLQStore is an optional dead-letter queue store. If nil, DLQ insertion is skipped.
	DLQStore dlq.Store

	DepositWitnessRefresher DepositWitnessRefresher
	ReadinessChecker        ReadinessChecker
	RuntimeSettings         RuntimeSettingsProvider
	BridgeSettings          BridgeSettingsProvider
	TipHeightProvider       TipHeightProvider
	ReceiptReader           ReceiptReader
	ProofStore              ProofStore

	Now func() time.Time
}

type DepositEvent struct {
	Commitment  common.Hash
	LeafIndex   uint64
	Amount      uint64
	JunoHeight  int64
	Memo        []byte
	SourceEvent *deposit.SourceEvent
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

	proofAttempts map[common.Hash]int // per-batch proof attempt count

	quorumVerifier *checkpoint.QuorumVerifier

	checkpoint *checkpoint.Checkpoint
	opSigs     [][]byte

	readinessChecker ReadinessChecker
	runtimeSettings  RuntimeSettingsProvider
	bridgeSettings   BridgeSettingsProvider
	tipHeightReader  TipHeightProvider
	receiptReader    ReceiptReader
	proofStore       ProofStore

	// pauseChecker is an optional bridge pause checker.
	pauseChecker PauseChecker
}

// PauseChecker checks whether the bridge contract is paused.
type PauseChecker interface {
	IsPaused(ctx context.Context) (bool, error)
}

type mintBatchItem struct {
	ID               [32]byte
	Mint             bridgeabi.MintItem
	ProofWitnessItem []byte
}

type durableMintBatch struct {
	Meta  deposit.Batch
	Items []mintBatchItem
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
	if cfg.ProofRequestTimeout <= 0 {
		cfg.ProofRequestTimeout = 15 * time.Minute
	}
	if cfg.ClaimTTL <= 0 {
		cfg.ClaimTTL = cfg.ProofRequestTimeout + 2*time.Minute
	}
	if cfg.ProofPriority < 0 {
		return nil, fmt.Errorf("%w: ProofPriority must be >= 0", ErrInvalidConfig)
	}
	if cfg.MaxProofAttempts == 0 {
		cfg.MaxProofAttempts = 3
	}
	if len(cfg.OWalletIVKBytes) != 64 {
		return nil, fmt.Errorf("%w: OWalletIVKBytes must be exactly 64 bytes", ErrInvalidConfig)
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
		proofAttempts:      make(map[common.Hash]int),
		quorumVerifier:     quorumVerifier,
		readinessChecker:   cfg.ReadinessChecker,
		runtimeSettings:    cfg.RuntimeSettings,
		bridgeSettings:     cfg.BridgeSettings,
		tipHeightReader:    cfg.TipHeightProvider,
		receiptReader:      cfg.ReceiptReader,
		proofStore:         cfg.ProofStore,
	}, nil
}

// WithPauseChecker sets an optional bridge pause checker.
func (r *Relayer) WithPauseChecker(pc PauseChecker) *Relayer {
	r.pauseChecker = pc
	return r
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
	if ev.JunoHeight < 0 {
		return fmt.Errorf("%w: juno height must be >= 0", ErrInvalidEvent)
	}
	if ev.JunoHeight == 0 && r.tipHeightReader != nil {
		return fmt.Errorf("%w: juno height must be > 0", ErrInvalidEvent)
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

	idBytes, err := idempotency.DepositIDV1([32]byte(ev.Commitment), ev.LeafIndex)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, err)
	}
	dep := deposit.Deposit{
		DepositID:        idBytes,
		Commitment:       [32]byte(ev.Commitment),
		LeafIndex:        ev.LeafIndex,
		Amount:           ev.Amount,
		BaseRecipient:    [20]byte(recipient),
		SourceEvent:      cloneSourceEvent(ev.SourceEvent),
		ProofWitnessItem: append([]byte(nil), ev.ProofWitnessItem...),
		JunoHeight:       ev.JunoHeight,
	}
	var job deposit.Job
	if ev.JunoHeight > 0 {
		job, _, err = r.store.UpsertSeen(ctx, dep)
	} else {
		job, _, err = r.store.UpsertConfirmed(ctx, dep)
	}
	if err != nil {
		return err
	}
	if job.State != deposit.StateConfirmed && job.State != deposit.StateSeen {
		return nil
	}
	return r.refillFromStore(ctx)
}

func (r *Relayer) FlushDue(ctx context.Context) error {
	if !r.ready(ctx) {
		return nil
	}
	if err := r.recoverSubmittedAttempts(ctx); err != nil {
		return err
	}
	if r.checkpoint == nil || len(r.opSigs) == 0 {
		return nil
	}
	if err := r.refillFromStore(ctx); err != nil {
		return err
	}
	return nil
}

func (r *Relayer) Flush(ctx context.Context) error {
	if !r.ready(ctx) {
		return nil
	}
	if err := r.recoverSubmittedAttempts(ctx); err != nil {
		return err
	}
	if r.checkpoint == nil || len(r.opSigs) == 0 {
		return nil
	}
	if err := r.refillFromStore(ctx); err != nil {
		return err
	}
	return nil
}

func (r *Relayer) refillFromStore(ctx context.Context) error {
	if !r.ready(ctx) {
		return nil
	}
	if r.checkpoint == nil || len(r.opSigs) == 0 {
		return nil
	}

	limit := r.cfg.MaxItems * 4
	if limit < r.cfg.MaxItems {
		limit = r.cfg.MaxItems
	}
	if err := r.promoteSeenDeposits(ctx, limit); err != nil {
		return err
	}
	jobs, err := r.store.ClaimConfirmed(ctx, r.cfg.Owner, r.cfg.ClaimTTL, limit)
	if err != nil {
		return err
	}

	minDeposit, err := r.currentMinDepositAmount(ctx)
	if err != nil {
		return err
	}

	for _, job := range jobs {
		if minDeposit > 0 && job.Deposit.Amount < minDeposit {
			if err := r.store.MarkRejected(ctx, job.Deposit.DepositID, belowMinDepositReason(minDeposit), [32]byte{}); err != nil {
				return fmt.Errorf("depositrelayer: reject below-min deposit %x: %w", job.Deposit.DepositID[:8], err)
			}
		}
	}

	nextBatchID := r.nextDurableBatchID()
	batch, ready, err := r.store.PrepareNextBatch(
		ctx,
		r.cfg.Owner,
		r.cfg.ClaimTTL,
		nextBatchID,
		r.cfg.MaxItems,
		r.cfg.MaxAge,
		limit,
		r.cfg.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("depositrelayer: prepare durable batch: %w", err)
	}
	if batch.BatchID == ([32]byte{}) || !ready {
		return nil
	}

	durableBatch, err := r.loadDurableMintBatch(ctx, batch, minDeposit)
	if err != nil {
		return err
	}
	if durableBatch.Meta.BatchID == ([32]byte{}) {
		return nil
	}
	if err := r.submitBatch(ctx, durableBatch); err != nil {
		return err
	}
	return nil
}

func checkpointCoversDepositHeight(cp checkpoint.Checkpoint, dep deposit.Deposit) bool {
	if dep.JunoHeight <= 0 {
		return true
	}
	return cp.Height >= uint64(dep.JunoHeight)
}

func (r *Relayer) nextDurableBatchID() [32]byte {
	return [32]byte(crypto.Keccak256Hash([]byte("deposit-durable-batch-v1|" + r.cfg.Owner + "|" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10))))
}

func (r *Relayer) loadDurableMintBatch(ctx context.Context, batch deposit.Batch, minDeposit uint64) (durableMintBatch, error) {
	if len(batch.DepositIDs) == 0 {
		return durableMintBatch{}, nil
	}

	items := make([]mintBatchItem, 0, len(batch.DepositIDs))
	rejected := make([][32]byte, 0)
	for _, depositID := range batch.DepositIDs {
		job, err := r.store.Get(ctx, depositID)
		if err != nil {
			return durableMintBatch{}, fmt.Errorf("depositrelayer: load batch deposit %x: %w", depositID[:8], err)
		}
		if minDeposit > 0 && job.Deposit.Amount < minDeposit {
			rejected = append(rejected, depositID)
			continue
		}
		if !checkpointCoversDepositHeight(*r.checkpoint, job.Deposit) {
			return durableMintBatch{}, nil
		}
		items = append(items, mintBatchItem{
			ID: depositID,
			Mint: bridgeabi.MintItem{
				DepositId: common.Hash(job.Deposit.DepositID),
				Recipient: common.Address(job.Deposit.BaseRecipient),
				Amount:    new(big.Int).SetUint64(job.Deposit.Amount),
			},
			ProofWitnessItem: append([]byte(nil), job.Deposit.ProofWitnessItem...),
		})
	}

	if len(rejected) > 0 {
		if err := r.store.FailBatch(ctx, r.cfg.Owner, batch.BatchID, belowMinDepositReason(minDeposit), rejected); err != nil {
			return durableMintBatch{}, fmt.Errorf("depositrelayer: fail durable batch for below-min deposits: %w", err)
		}
		return durableMintBatch{}, nil
	}
	if len(items) == 0 {
		return durableMintBatch{}, nil
	}
	return durableMintBatch{Meta: batch, Items: items}, nil
}

func (r *Relayer) recoverSubmittedAttempts(ctx context.Context) error {
	if !r.ready(ctx) {
		return nil
	}
	limit := r.cfg.MaxItems * 4
	if limit < r.cfg.MaxItems {
		limit = r.cfg.MaxItems
	}
	attempts, err := r.store.ClaimSubmittedAttempts(ctx, r.cfg.Owner, r.cfg.ClaimTTL, limit)
	if err != nil {
		return err
	}

	for _, attempt := range attempts {
		if attempt.TxHash != ([32]byte{}) {
			if err := r.reconcileSubmittedAttempt(ctx, attempt); err != nil {
				return fmt.Errorf("depositrelayer: reconcile recovered batch: %w", err)
			}
			continue
		}
		if r.currentCheckpointSupersedes(attempt.Checkpoint) {
			if err := r.store.RequeueSubmittedBatch(ctx, attempt.BatchID); err != nil {
				return fmt.Errorf("depositrelayer: requeue stale submitted batch: %w", err)
			}
			r.log.Info("requeued stale submitted batch",
				"batchID", fmt.Sprintf("%x", attempt.BatchID[:8]),
				"attemptCheckpointHeight", attempt.Checkpoint.Height,
				"currentCheckpointHeight", r.checkpoint.Height,
			)
			continue
		}
		if err := r.resubmitSubmittedAttempt(ctx, attempt); err != nil {
			return err
		}
	}
	return nil
}

func (r *Relayer) currentCheckpointSupersedes(attempt checkpoint.Checkpoint) bool {
	if r == nil || r.checkpoint == nil {
		return false
	}
	if r.checkpoint.BaseChainID != attempt.BaseChainID || r.checkpoint.BridgeContract != attempt.BridgeContract {
		return false
	}
	return r.checkpoint.Height > attempt.Height
}

func (r *Relayer) ready(ctx context.Context) bool {
	if r.readinessChecker == nil {
		goto runtime
	}
	if r.readinessChecker.Ready(ctx) != nil {
		return false
	}

runtime:
	if r.runtimeSettings != nil && r.runtimeSettings.Ready(ctx) != nil {
		return false
	}
	if r.bridgeSettings != nil && r.bridgeSettings.Ready(ctx) != nil {
		return false
	}
	return true
}

func (r *Relayer) resubmitSubmittedAttempt(ctx context.Context, attempt deposit.SubmittedBatchAttempt) error {
	if err := r.checkBridgePause(ctx); err != nil {
		return err
	}

	items, err := r.loadMintItems(ctx, attempt.DepositIDs)
	if err != nil {
		return err
	}

	journal, err := bridgeabi.EncodeDepositJournal(bridgeabi.DepositJournal{
		FinalOrchardRoot: attempt.Checkpoint.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(attempt.Checkpoint.BaseChainID),
		BridgeContract:   attempt.Checkpoint.BridgeContract,
		Items:            items,
	})
	if err != nil {
		return err
	}
	calldata, err := bridgeabi.PackMintBatchCalldata(attempt.Checkpoint, attempt.OperatorSignatures, attempt.ProofSeal, journal)
	if err != nil {
		return err
	}

	req := httpapi.SendRequest{
		To:       attempt.Checkpoint.BridgeContract.Hex(),
		Data:     hexutil.Encode(calldata),
		GasLimit: r.cfg.GasLimit,
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
	if err := r.store.SetBatchSubmissionTxHash(ctx, attempt.BatchID, [32]byte(txHash)); err != nil {
		return fmt.Errorf("depositrelayer: set batch tx hash: %w", err)
	}
	if err := r.applyBatchOutcomeFromHash(ctx, attempt.BatchID, attempt.DepositIDs, attempt.Checkpoint, attempt.ProofSeal, [32]byte(txHash)); err != nil {
		return err
	}

	r.log.Info("resubmitted mintBatch",
		"checkpointHeight", attempt.Checkpoint.Height,
		"items", len(items),
		"txHash", res.TxHash,
	)
	return nil
}

func (r *Relayer) loadMintItems(ctx context.Context, depositIDs [][32]byte) ([]bridgeabi.MintItem, error) {
	items := make([]bridgeabi.MintItem, 0, len(depositIDs))
	for _, depositID := range depositIDs {
		job, err := r.store.Get(ctx, depositID)
		if err != nil {
			return nil, fmt.Errorf("depositrelayer: load submitted deposit %x: %w", depositID[:8], err)
		}
		items = append(items, bridgeabi.MintItem{
			DepositId: common.Hash(job.Deposit.DepositID),
			Recipient: common.Address(job.Deposit.BaseRecipient),
			Amount:    new(big.Int).SetUint64(job.Deposit.Amount),
		})
	}
	return items, nil
}

func (r *Relayer) submitBatch(ctx context.Context, batch durableMintBatch) error {
	if len(batch.Items) == 0 {
		return nil
	}

	if err := r.checkBridgePause(ctx); err != nil {
		return err
	}

	cp := *r.checkpoint
	opSigs := r.opSigs
	if batch.Meta.Checkpoint == cp && len(batch.Meta.OperatorSignatures) > 0 {
		opSigs = batch.Meta.OperatorSignatures
	}

	// Check per-batch proof attempt limits.
	depositIDs := make([]common.Hash, 0, len(batch.Items))
	for _, it := range batch.Items {
		depositIDs = append(depositIDs, common.Hash(it.ID))
	}
	proofBatchID := idempotency.DepositBatchIDV1(depositIDs)
	if r.cfg.MaxProofAttempts > 0 {
		r.proofAttempts[proofBatchID]++
		attempts := r.proofAttempts[proofBatchID]
		if attempts >= r.cfg.MaxProofAttempts {
			if err := r.maybeDLQDepositBatch(ctx, batch.Meta.BatchID, batch, "proof", "proof_attempts_exhausted",
				fmt.Sprintf("exceeded max proof attempts (%d)", r.cfg.MaxProofAttempts), attempts); err != nil {
				return err
			}
			delete(r.proofAttempts, proofBatchID)
			return fmt.Errorf("%w: batch %x after %d attempts", ErrProofAttemptsExhausted, proofBatchID[:8], attempts)
		}
	}

	items := make([]bridgeabi.MintItem, 0, len(batch.Items))
	witnessItems := make([][]byte, 0, len(batch.Items))
	for i, it := range batch.Items {
		items = append(items, it.Mint)
		witness := append([]byte(nil), it.ProofWitnessItem...)
		if len(r.cfg.OWalletIVKBytes) == 64 && r.cfg.DepositWitnessRefresher != nil {
			if cp.Height > math.MaxInt64 {
				return fmt.Errorf("depositrelayer: checkpoint height %d exceeds int64", cp.Height)
			}
			refreshedRoot, refreshedWitness, err := r.cfg.DepositWitnessRefresher.RefreshDepositWitness(
				ctx,
				int64(cp.Height),
				witness,
			)
			if err != nil {
				return fmt.Errorf("depositrelayer: refresh proof witness item for batch index %d: %w", i, err)
			}
			if refreshedRoot != cp.FinalOrchardRoot {
				return fmt.Errorf(
					"depositrelayer: refreshed witness root %s does not match checkpoint root %s for batch index %d",
					refreshedRoot.Hex(),
					cp.FinalOrchardRoot.Hex(),
					i,
				)
			}
			witness = refreshedWitness
		}
		witnessItems = append(witnessItems, witness)
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

	seal := append([]byte(nil), batch.Meta.ProofSeal...)
	needsFreshProof := batch.Meta.State != deposit.BatchStateProofReady || batch.Meta.Checkpoint != cp || len(seal) == 0
	if needsFreshProof {
		if _, err := r.store.MarkBatchProofRequested(ctx, r.cfg.Owner, batch.Meta.BatchID, cp); err != nil {
			return fmt.Errorf("depositrelayer: mark batch proof requested %x: %w", batch.Meta.BatchID[:8], err)
		}

		privateInput, err := r.encodePrivateInput(cp, opSigs, items, witnessItems)
		if err != nil {
			return err
		}

		jobID := idempotency.ProofJobIDV1("deposit", proofBatchID, r.cfg.DepositImageID, journal, privateInput)
		pctx, cancel := context.WithTimeout(ctx, r.cfg.ProofRequestTimeout)
		defer cancel()

		proofRes, proofFailure, recovered, err := r.lookupProofOutcome(ctx, jobID)
		if err != nil {
			return err
		}
		if recovered {
			if proofFailure != nil {
				return r.rejectBatchForProofFailure(ctx, batch.Meta.BatchID, batch, *proofFailure)
			}
		} else {
			proofRes, err = r.prover.RequestProof(pctx, proofclient.Request{
				JobID:        jobID,
				Pipeline:     "deposit",
				ImageID:      r.cfg.DepositImageID,
				Journal:      journal,
				PrivateInput: privateInput,
				Deadline:     r.cfg.Now().Add(r.cfg.ProofRequestTimeout),
				Priority:     r.cfg.ProofPriority,
			})
			if err != nil {
				recoveredRes, proofFailure, recovered, recoverErr := r.lookupProofOutcome(ctx, jobID)
				if recoverErr != nil {
					return recoverErr
				}
				if recovered {
					if proofFailure != nil {
						return r.rejectBatchForProofFailure(ctx, batch.Meta.BatchID, batch, *proofFailure)
					}
					proofRes = recoveredRes
				} else {
					var fail *proofclient.FailureError
					if errors.As(err, &fail) && !fail.Retryable {
						return r.rejectBatchForProofFailure(ctx, batch.Meta.BatchID, batch, *fail)
					}
					return err
				}
			}
		}
		seal = proofRes.Seal
		if len(seal) == 0 {
			return fmt.Errorf("depositrelayer: empty proof seal from proof requester")
		}
		if updatedBatch, err := r.store.MarkBatchProofReady(ctx, r.cfg.Owner, batch.Meta.BatchID, cp, opSigs, seal); err != nil {
			return fmt.Errorf("depositrelayer: mark batch proof ready %x: %w", batch.Meta.BatchID[:8], err)
		} else {
			batch.Meta = updatedBatch
		}
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
	if _, err := r.store.MarkBatchSubmitted(ctx, r.cfg.Owner, batch.Meta.BatchID, finalizeIDs, cp, opSigs, seal); err != nil {
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
		revertDetail := strings.TrimSpace(res.Receipt.RevertReason)
		if revertDetail == "" {
			revertDetail = strings.TrimSpace(res.Receipt.RevertData)
		}
		errorMessage := fmt.Sprintf("mintBatch tx reverted: %s", res.TxHash)
		if revertDetail != "" {
			errorMessage = fmt.Sprintf("%s (%s)", errorMessage, revertDetail)
		}
		if err := r.maybeDLQDepositBatch(ctx, batch.Meta.BatchID, batch, "bridge_tx", "tx_reverted",
			errorMessage, 0); err != nil {
			return err
		}
		if revertDetail != "" {
			return fmt.Errorf("depositrelayer: mintBatch tx reverted: %s", revertDetail)
		}
		return fmt.Errorf("depositrelayer: mintBatch tx reverted")
	}

	txHash := common.HexToHash(res.TxHash)
	if err := r.store.SetBatchSubmissionTxHash(ctx, batch.Meta.BatchID, [32]byte(txHash)); err != nil {
		return fmt.Errorf("depositrelayer: set batch tx hash: %w", err)
	}
	if err := r.applyBatchOutcomeFromHash(ctx, batch.Meta.BatchID, finalizeIDs, cp, seal, [32]byte(txHash)); err != nil {
		return err
	}

	// Clear proof attempt counter on success.
	delete(r.proofAttempts, proofBatchID)

	r.log.Info("submitted mintBatch",
		"checkpointHeight", cp.Height,
		"items", len(items),
		"txHash", res.TxHash,
	)
	return nil
}

func (r *Relayer) checkBridgePause(ctx context.Context) error {
	if r.pauseChecker == nil {
		return nil
	}
	paused, err := r.pauseChecker.IsPaused(ctx)
	if err != nil {
		r.log.Warn("bridge pause check error (fail-safe: skipping submit)", "err", err)
		return fmt.Errorf("depositrelayer: pause check failed: %w", err)
	}
	if paused {
		r.log.Warn("bridge is paused, skipping batch submission")
		return fmt.Errorf("depositrelayer: bridge is paused, skipping submit")
	}
	return nil
}

func cloneSourceEvent(src *deposit.SourceEvent) *deposit.SourceEvent {
	if src == nil {
		return nil
	}
	out := *src
	return &out
}

// maybeDLQDepositBatch inserts a deposit batch into the dead-letter queue.
// If DLQStore is nil, this is a no-op.
func (r *Relayer) maybeDLQDepositBatch(ctx context.Context, batchID [32]byte, batch durableMintBatch, failureStage, errorCode, errorMessage string, attemptCount int) error {
	if r.cfg.DLQStore == nil {
		return nil
	}

	ids := make([][32]byte, 0, len(batch.Items))
	for _, it := range batch.Items {
		ids = append(ids, it.ID)
	}

	rec := dlq.DepositBatchDLQRecord{
		BatchID:      batchID,
		DepositIDs:   ids,
		ItemsCount:   len(ids),
		State:        int16(deposit.StateConfirmed),
		FailureStage: failureStage,
		ErrorCode:    errorCode,
		ErrorMessage: errorMessage,
		AttemptCount: attemptCount,
	}

	if err := r.cfg.DLQStore.InsertDepositBatchDLQ(ctx, rec); err != nil {
		r.log.Error("depositrelayer: failed to insert into DLQ",
			"batch_id", fmt.Sprintf("%x", batchID[:8]),
			"failure_stage", failureStage,
			"err", err,
		)
		return fmt.Errorf("depositrelayer: insert deposit batch DLQ: %w", err)
	}
	r.log.Info("depositrelayer: inserted batch into DLQ",
		"batch_id", fmt.Sprintf("%x", batchID[:8]),
		"failure_stage", failureStage,
		"items", len(ids),
	)
	return nil
}

func (r *Relayer) lookupProofOutcome(ctx context.Context, jobID common.Hash) (proofclient.Result, *proofclient.FailureError, bool, error) {
	if r.proofStore == nil {
		return proofclient.Result{}, nil, false, nil
	}
	rec, err := r.proofStore.GetJob(ctx, jobID)
	if err != nil {
		if errors.Is(err, proof.ErrNotFound) {
			return proofclient.Result{}, nil, false, nil
		}
		return proofclient.Result{}, nil, false, fmt.Errorf("depositrelayer: load proof job %s: %w", jobID.Hex(), err)
	}
	switch rec.State {
	case proof.StateFulfilled:
		return proofclient.Result{
			Seal:     append([]byte(nil), rec.Seal...),
			Metadata: cloneProofMetadata(rec.Metadata),
		}, nil, true, nil
	case proof.StateFailedTerminal:
		return proofclient.Result{}, &proofclient.FailureError{
			Code:      rec.ErrorCode,
			Retryable: false,
			Message:   rec.ErrorMessage,
		}, true, nil
	default:
		return proofclient.Result{}, nil, false, nil
	}
}

func (r *Relayer) rejectBatchForProofFailure(
	ctx context.Context,
	batchID [32]byte,
	batch durableMintBatch,
	failure proofclient.FailureError,
) error {
	if err := r.maybeDLQDepositBatch(ctx, batchID, batch, "proof", strings.TrimSpace(failure.Code), strings.TrimSpace(failure.Message), 0); err != nil {
		return err
	}
	reason := proofFailureReason(failure)
	rejectedIDs := make([][32]byte, 0, len(batch.Items))
	for _, it := range batch.Items {
		rejectedIDs = append(rejectedIDs, it.ID)
	}
	if err := r.store.FailBatch(ctx, r.cfg.Owner, batchID, reason, rejectedIDs); err != nil {
		return fmt.Errorf("depositrelayer: fail proof-failed batch %x: %w", batchID[:8], err)
	}
	delete(r.proofAttempts, idempotency.DepositBatchIDV1(batchDepositHashes(batch.Items)))
	r.log.Error("depositrelayer: rejected batch after terminal proof failure",
		"batch_id", common.Hash(batchID).Hex(),
		"error_code", failure.Code,
		"message", failure.Message,
		"items", len(batch.Items),
	)
	return nil
}

func batchDepositHashes(items []mintBatchItem) []common.Hash {
	out := make([]common.Hash, 0, len(items))
	for _, item := range items {
		out = append(out, common.Hash(item.ID))
	}
	return out
}

func batchIDsToHashes(ids [][32]byte) []common.Hash {
	out := make([]common.Hash, 0, len(ids))
	for _, id := range ids {
		out = append(out, common.Hash(id))
	}
	return out
}

func proofFailureReason(failure proofclient.FailureError) string {
	code := strings.TrimSpace(failure.Code)
	if code != "" {
		return "proof failed: " + code
	}
	message := strings.TrimSpace(failure.Message)
	if message != "" {
		return "proof failed: " + message
	}
	return "proof failed"
}

func cloneProofMetadata(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (r *Relayer) encodePrivateInput(cp checkpoint.Checkpoint, opSigs [][]byte, items []bridgeabi.MintItem, witnessItems [][]byte) ([]byte, error) {
	_ = opSigs
	_ = items

	if len(r.cfg.OWalletIVKBytes) != 64 {
		return nil, fmt.Errorf("depositrelayer: missing required OWallet IVK")
	}
	var ivk [64]byte
	copy(ivk[:], r.cfg.OWalletIVKBytes)
	for i, w := range witnessItems {
		if len(w) == 0 {
			return nil, fmt.Errorf("depositrelayer: missing proof witness item for batch index %d", i)
		}
	}
	return proverinput.EncodeDepositGuestPrivateInput(cp, ivk, witnessItems)
}

func (r *Relayer) promoteSeenDeposits(ctx context.Context, limit int) error {
	if r.tipHeightReader == nil {
		return nil
	}
	settings, err := r.currentRuntimeSettings()
	if err != nil {
		return err
	}
	tipHeight, err := r.tipHeightReader.TipHeight(ctx)
	if err != nil {
		return fmt.Errorf("depositrelayer: load juno tip height: %w", err)
	}
	if _, err := r.store.PromoteSeenToConfirmed(ctx, tipHeight, settings.DepositMinConfirmations, limit); err != nil {
		return fmt.Errorf("depositrelayer: promote seen deposits: %w", err)
	}
	return nil
}

func (r *Relayer) currentRuntimeSettings() (runtimeconfig.Settings, error) {
	if r.runtimeSettings == nil {
		return runtimeconfig.Settings{
			DepositMinConfirmations:         1,
			WithdrawPlannerMinConfirmations: 1,
			WithdrawBatchConfirmations:      1,
		}, nil
	}
	settings, err := r.runtimeSettings.Current()
	if err != nil {
		return runtimeconfig.Settings{}, fmt.Errorf("depositrelayer: load runtime settings: %w", err)
	}
	return settings, nil
}

func (r *Relayer) currentMinDepositAmount(ctx context.Context) (uint64, error) {
	if r.bridgeSettings == nil {
		return 0, nil
	}
	snapshot, err := r.bridgeSettings.Current()
	if err != nil {
		return 0, fmt.Errorf("depositrelayer: load bridge settings: %w", err)
	}
	return snapshot.MinDepositAmount, nil
}

func (r *Relayer) reconcileSubmittedAttempt(ctx context.Context, attempt deposit.SubmittedBatchAttempt) error {
	if r.receiptReader == nil {
		if err := r.store.FinalizeBatch(ctx, attempt.DepositIDs, attempt.Checkpoint, attempt.ProofSeal, attempt.TxHash); err != nil {
			return fmt.Errorf("depositrelayer: finalize batch without receipt reader: %w", err)
		}
		delete(r.proofAttempts, idempotency.DepositBatchIDV1(batchIDsToHashes(attempt.DepositIDs)))
		return nil
	}

	receipt, err := r.receiptReader.TransactionReceipt(ctx, common.Hash(attempt.TxHash))
	if err != nil {
		if errors.Is(err, ethereum.NotFound) {
			return nil
		}
		return fmt.Errorf("depositrelayer: fetch receipt for recovered batch: %w", err)
	}
	return r.applyBatchOutcome(ctx, attempt.BatchID, attempt.DepositIDs, attempt.TxHash, receipt)
}

func (r *Relayer) applyBatchOutcomeFromHash(ctx context.Context, batchID [32]byte, depositIDs [][32]byte, cp checkpoint.Checkpoint, seal []byte, txHash [32]byte) error {
	if r.receiptReader == nil {
		if err := r.store.FinalizeBatch(ctx, depositIDs, cp, seal, txHash); err != nil {
			return fmt.Errorf("depositrelayer: finalize batch without receipt reader: %w", err)
		}
		delete(r.proofAttempts, idempotency.DepositBatchIDV1(batchIDsToHashes(depositIDs)))
		return nil
	}
	receipt, err := r.receiptReader.TransactionReceipt(ctx, common.Hash(txHash))
	if err != nil {
		return fmt.Errorf("depositrelayer: fetch receipt for batch: %w", err)
	}
	return r.applyBatchOutcome(ctx, batchID, depositIDs, txHash, receipt)
}

func (r *Relayer) applyBatchOutcome(ctx context.Context, batchID [32]byte, depositIDs [][32]byte, txHash [32]byte, receipt *types.Receipt) error {
	if receipt == nil {
		return fmt.Errorf("depositrelayer: missing batch receipt")
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("depositrelayer: mintBatch tx reverted")
	}

	finalizedIDs, rejectedIDs, err := bridgeabi.DecodeMintBatchLogOutcomes(receipt.Logs, r.cfg.BridgeAddress)
	if err != nil {
		return fmt.Errorf("depositrelayer: decode batch receipt logs: %w", err)
	}
	recoveredFinalized, rejectedIDs, err := r.resolveDuplicateSkippedDeposits(ctx, rejectedIDs, receipt.BlockNumber)
	if err != nil {
		return fmt.Errorf("depositrelayer: reconcile skipped deposits: %w", err)
	}

	if err := r.store.ApplyBatchOutcome(ctx, batchID, txHash, finalizedIDs, rejectedIDs, belowMinDepositReason(0)); err != nil {
		return fmt.Errorf("depositrelayer: apply batch receipt outcome: %w", err)
	}
	for depositID, mintedTxHash := range recoveredFinalized {
		if err := r.store.RepairFinalized(ctx, depositID, mintedTxHash); err != nil {
			return fmt.Errorf("depositrelayer: repair duplicate skipped deposit %x: %w", depositID[:], err)
		}
	}

	unresolved := unresolvedDepositIDs(depositIDs, appendRecoveredFinalized(finalizedIDs, recoveredFinalized), rejectedIDs)
	if len(unresolved) > 0 {
		r.log.Error("mintBatch receipt left unresolved deposits",
			"batchID", fmt.Sprintf("%x", batchID[:]),
			"txHash", fmt.Sprintf("%x", txHash[:]),
			"unresolved", len(unresolved),
		)
	}
	delete(r.proofAttempts, idempotency.DepositBatchIDV1(batchIDsToHashes(depositIDs)))
	return nil
}

func (r *Relayer) resolveDuplicateSkippedDeposits(ctx context.Context, rejectedIDs [][32]byte, toBlock *big.Int) (map[[32]byte][32]byte, [][32]byte, error) {
	if len(rejectedIDs) == 0 {
		return map[[32]byte][32]byte{}, nil, nil
	}
	mintedTxHashes, err := bridgeabi.FindMintedDepositTxHashes(ctx, r.receiptReader, r.cfg.BridgeAddress, rejectedIDs, toBlock)
	if err != nil {
		return nil, nil, err
	}
	stillRejected := make([][32]byte, 0, len(rejectedIDs))
	for _, depositID := range rejectedIDs {
		if _, ok := mintedTxHashes[depositID]; ok {
			continue
		}
		stillRejected = append(stillRejected, depositID)
	}
	return mintedTxHashes, stillRejected, nil
}

func appendRecoveredFinalized(finalizedIDs [][32]byte, recovered map[[32]byte][32]byte) [][32]byte {
	if len(recovered) == 0 {
		return finalizedIDs
	}
	out := make([][32]byte, 0, len(finalizedIDs)+len(recovered))
	out = append(out, finalizedIDs...)
	for depositID := range recovered {
		out = append(out, depositID)
	}
	return out
}

func unresolvedDepositIDs(expected [][32]byte, finalized [][32]byte, rejected [][32]byte) [][32]byte {
	finalizedSet := make(map[[32]byte]struct{}, len(finalized))
	for _, id := range finalized {
		finalizedSet[id] = struct{}{}
	}
	rejectedSet := make(map[[32]byte]struct{}, len(rejected))
	for _, id := range rejected {
		rejectedSet[id] = struct{}{}
	}
	out := make([][32]byte, 0, len(expected))
	for _, id := range expected {
		if _, ok := finalizedSet[id]; ok {
			continue
		}
		if _, ok := rejectedSet[id]; ok {
			continue
		}
		out = append(out, id)
	}
	return out
}

func belowMinDepositReason(minDeposit uint64) string {
	if minDeposit == 0 {
		return "deposit skipped by bridge"
	}
	return fmt.Sprintf("deposit amount is below the current minimum deposit (%d)", minDeposit)
}
