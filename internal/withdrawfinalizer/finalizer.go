package withdrawfinalizer

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/blobstore"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/idempotency"
	"github.com/juno-intents/intents-juno/internal/leases"
	"github.com/juno-intents/intents-juno/internal/proofclient"
	"github.com/juno-intents/intents-juno/internal/proverinput"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

var (
	ErrInvalidConfig     = errors.New("withdrawfinalizer: invalid config")
	ErrInvalidCheckpoint = errors.New("withdrawfinalizer: invalid checkpoint")
)

type Sender interface {
	Send(ctx context.Context, req httpapi.SendRequest) (httpapi.SendResponse, error)
}

type CheckpointPackage struct {
	Checkpoint         checkpoint.Checkpoint
	OperatorSignatures [][]byte
}

type Config struct {
	Owner    string
	LeaseTTL time.Duration

	MaxBatches int

	BaseChainID     uint64
	BridgeAddress   common.Address
	WithdrawImageID common.Hash

	OperatorAddresses []common.Address
	OperatorThreshold int

	GasLimit uint64

	ProofRequestTimeout time.Duration
	ProofPriority       int
}

type Finalizer struct {
	cfg Config

	store      withdraw.Store
	leaseStore leases.Store
	sender     Sender
	prover     proofclient.Client
	blobStore  blobstore.Store

	log *slog.Logger

	quorumVerifier *checkpoint.QuorumVerifier

	checkpoint *checkpoint.Checkpoint
	opSigs     [][]byte
}

func New(cfg Config, store withdraw.Store, leaseStore leases.Store, sender Sender, prover proofclient.Client, log *slog.Logger) (*Finalizer, error) {
	if store == nil || leaseStore == nil || sender == nil || prover == nil {
		return nil, fmt.Errorf("%w: nil dependency", ErrInvalidConfig)
	}
	if cfg.Owner == "" {
		return nil, fmt.Errorf("%w: missing owner", ErrInvalidConfig)
	}
	if cfg.LeaseTTL <= 0 {
		return nil, fmt.Errorf("%w: LeaseTTL must be > 0", ErrInvalidConfig)
	}
	if cfg.MaxBatches <= 0 {
		return nil, fmt.Errorf("%w: MaxBatches must be > 0", ErrInvalidConfig)
	}
	if cfg.BaseChainID == 0 {
		return nil, fmt.Errorf("%w: BaseChainID must be non-zero", ErrInvalidConfig)
	}
	if (cfg.BridgeAddress == common.Address{}) {
		return nil, fmt.Errorf("%w: BridgeAddress must be non-zero", ErrInvalidConfig)
	}
	if len(cfg.OperatorAddresses) == 0 {
		return nil, fmt.Errorf("%w: OperatorAddresses must be non-empty", ErrInvalidConfig)
	}
	if cfg.OperatorThreshold <= 0 {
		return nil, fmt.Errorf("%w: OperatorThreshold must be > 0", ErrInvalidConfig)
	}
	if cfg.ProofRequestTimeout <= 0 {
		cfg.ProofRequestTimeout = 15 * time.Minute
	}
	if cfg.ProofPriority < 0 {
		return nil, fmt.Errorf("%w: ProofPriority must be >= 0", ErrInvalidConfig)
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	quorumVerifier, err := checkpoint.NewQuorumVerifier(cfg.OperatorAddresses, cfg.OperatorThreshold)
	if err != nil {
		return nil, err
	}

	return &Finalizer{
		cfg:            cfg,
		store:          store,
		leaseStore:     leaseStore,
		sender:         sender,
		prover:         prover,
		log:            log,
		quorumVerifier: quorumVerifier,
	}, nil
}

// WithBlobStore configures optional artifact persistence for proof inputs/outputs.
func (f *Finalizer) WithBlobStore(store blobstore.Store) *Finalizer {
	f.blobStore = store
	return f
}

func (f *Finalizer) IngestCheckpoint(ctx context.Context, pkg CheckpointPackage) error {
	cp := pkg.Checkpoint
	if cp.BaseChainID != f.cfg.BaseChainID {
		return fmt.Errorf("%w: baseChainID mismatch: want %d got %d", ErrInvalidCheckpoint, f.cfg.BaseChainID, cp.BaseChainID)
	}
	if cp.BridgeContract != f.cfg.BridgeAddress {
		return fmt.Errorf("%w: bridge mismatch: want %s got %s", ErrInvalidCheckpoint, f.cfg.BridgeAddress, cp.BridgeContract)
	}
	if _, err := f.quorumVerifier.VerifyCheckpointSignatures(cp, pkg.OperatorSignatures); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCheckpoint, err)
	}

	// Only move forward in height to avoid accidental reorg/rollback usage.
	if f.checkpoint != nil && cp.Height <= f.checkpoint.Height {
		return nil
	}

	f.checkpoint = &cp
	f.opSigs = pkg.OperatorSignatures

	f.log.Info("updated checkpoint", "height", cp.Height, "digest", checkpoint.Digest(cp))
	return f.Tick(ctx)
}

func (f *Finalizer) Tick(ctx context.Context) error {
	if f == nil || f.store == nil {
		return fmt.Errorf("%w: nil finalizer", ErrInvalidConfig)
	}
	if f.checkpoint == nil || len(f.opSigs) == 0 {
		return nil
	}

	batches, err := f.store.ListBatchesByState(ctx, withdraw.BatchStateConfirmed)
	if err != nil {
		return err
	}

	n := f.cfg.MaxBatches
	if n > len(batches) {
		n = len(batches)
	}
	for i := 0; i < n; i++ {
		b := batches[i]
		if err := f.finalizeBatch(ctx, b.ID); err != nil {
			return err
		}
	}
	return nil
}

func (f *Finalizer) finalizeBatch(ctx context.Context, batchID [32]byte) error {
	leaseName := batchLeaseName(batchID)
	if _, ok, err := f.leaseStore.TryAcquire(ctx, leaseName, f.cfg.Owner, f.cfg.LeaseTTL); err != nil {
		return err
	} else if !ok {
		return nil
	}
	defer func() { _ = f.leaseStore.Release(context.Background(), leaseName, f.cfg.Owner) }()

	b, err := f.store.GetBatch(ctx, batchID)
	if err != nil {
		return err
	}
	if b.State != withdraw.BatchStateConfirmed {
		// Already progressed.
		return nil
	}
	if err := f.store.MarkBatchFinalizing(ctx, batchID); err != nil {
		return err
	}

	cp := *f.checkpoint

	items := make([]bridgeabi.FinalizeItem, 0, len(b.WithdrawalIDs))
	for _, wid := range b.WithdrawalIDs {
		w, err := f.store.GetWithdrawal(ctx, wid)
		if err != nil {
			return err
		}

		_, net, err := withdraw.ComputeFeeAndNet(w.Amount, w.FeeBps)
		if err != nil {
			return err
		}

		items = append(items, bridgeabi.FinalizeItem{
			WithdrawalId:    common.Hash(w.ID),
			RecipientUAHash: crypto.Keccak256Hash(w.RecipientUA),
			NetAmount:       new(big.Int).SetUint64(net),
		})
	}

	journal, err := bridgeabi.EncodeWithdrawJournal(bridgeabi.WithdrawJournal{
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
		Items:            items,
	})
	if err != nil {
		return err
	}
	if err := f.persistProofJournalArtifact(ctx, batchID, journal); err != nil {
		return err
	}

	privateInput, err := proverinput.EncodeWithdrawPrivateInputV1(cp, f.opSigs, items)
	if err != nil {
		return err
	}
	if err := f.persistProofPrivateInputArtifact(ctx, batchID, privateInput); err != nil {
		return err
	}

	jobID := idempotency.ProofJobIDV1("withdraw", common.Hash(batchID), f.cfg.WithdrawImageID, journal, privateInput)
	pctx, cancel := context.WithTimeout(ctx, f.cfg.ProofRequestTimeout)
	defer cancel()

	proofRes, err := f.prover.RequestProof(pctx, proofclient.Request{
		JobID:        jobID,
		Pipeline:     "withdraw",
		ImageID:      f.cfg.WithdrawImageID,
		Journal:      journal,
		PrivateInput: privateInput,
		Deadline:     time.Now().UTC().Add(f.cfg.ProofRequestTimeout),
		Priority:     f.cfg.ProofPriority,
	})
	if err != nil {
		return err
	}
	seal := proofRes.Seal
	if len(seal) == 0 {
		return fmt.Errorf("withdrawfinalizer: empty proof seal from proof requester")
	}
	if err := f.persistProofSealArtifact(ctx, batchID, seal); err != nil {
		return err
	}

	calldata, err := bridgeabi.PackFinalizeWithdrawBatchCalldata(cp, f.opSigs, seal, journal)
	if err != nil {
		return err
	}

	req := httpapi.SendRequest{
		To:       cp.BridgeContract.Hex(),
		Data:     hexutil.Encode(calldata),
		GasLimit: f.cfg.GasLimit,
	}

	res, err := f.sender.Send(ctx, req)
	if err != nil {
		return err
	}
	if res.TxHash == "" {
		return fmt.Errorf("withdrawfinalizer: base-relayer did not return a tx hash")
	}
	if res.Receipt == nil {
		return fmt.Errorf("withdrawfinalizer: base-relayer did not return a receipt")
	}
	if res.Receipt.Status != 1 {
		return fmt.Errorf("withdrawfinalizer: finalizeWithdrawBatch tx reverted")
	}

	if err := f.store.SetBatchFinalized(ctx, batchID, res.TxHash); err != nil {
		// If another worker won the race, treat it as success.
		b2, err2 := f.store.GetBatch(ctx, batchID)
		if err2 == nil && b2.State == withdraw.BatchStateFinalized {
			return nil
		}
		return err
	}

	_ = f.leaseStore.Release(ctx, leaseName, f.cfg.Owner)

	f.log.Info("submitted finalizeWithdrawBatch",
		"checkpointHeight", cp.Height,
		"items", len(items),
		"txHash", res.TxHash,
	)
	return nil
}

func batchLeaseName(batchID [32]byte) string {
	return "withdraw-finalizer/batch/" + hex.EncodeToString(batchID[:])
}

func journalArtifactKey(batchID [32]byte) string {
	return "withdrawals/batches/" + hex.EncodeToString(batchID[:]) + "/proof/journal.bin"
}

func privateInputArtifactKey(batchID [32]byte) string {
	return "withdrawals/batches/" + hex.EncodeToString(batchID[:]) + "/proof/private_input.v1.bin"
}

func sealArtifactKey(batchID [32]byte) string {
	return "withdrawals/batches/" + hex.EncodeToString(batchID[:]) + "/proof/seal.bin"
}

func (f *Finalizer) persistProofJournalArtifact(ctx context.Context, batchID [32]byte, journal []byte) error {
	if f.blobStore == nil {
		return nil
	}
	if err := f.blobStore.Put(ctx, journalArtifactKey(batchID), journal, blobstore.PutOptions{
		ContentType: "application/octet-stream",
		Metadata: map[string]string{
			"artifact-type": "withdraw-proof-journal",
			"batch-id":      hex.EncodeToString(batchID[:]),
		},
	}); err != nil {
		return fmt.Errorf("withdrawfinalizer: persist proof journal artifact: %w", err)
	}
	return nil
}

func (f *Finalizer) persistProofPrivateInputArtifact(ctx context.Context, batchID [32]byte, privateInput []byte) error {
	if f.blobStore == nil {
		return nil
	}
	if err := f.blobStore.Put(ctx, privateInputArtifactKey(batchID), privateInput, blobstore.PutOptions{
		ContentType: "application/octet-stream",
		Metadata: map[string]string{
			"artifact-type": "withdraw-proof-private-input",
			"batch-id":      hex.EncodeToString(batchID[:]),
		},
	}); err != nil {
		return fmt.Errorf("withdrawfinalizer: persist proof private input artifact: %w", err)
	}
	return nil
}

func (f *Finalizer) persistProofSealArtifact(ctx context.Context, batchID [32]byte, seal []byte) error {
	if f.blobStore == nil {
		return nil
	}
	if err := f.blobStore.Put(ctx, sealArtifactKey(batchID), seal, blobstore.PutOptions{
		ContentType: "application/octet-stream",
		Metadata: map[string]string{
			"artifact-type": "withdraw-proof-seal",
			"batch-id":      hex.EncodeToString(batchID[:]),
		},
	}); err != nil {
		return fmt.Errorf("withdrawfinalizer: persist proof seal artifact: %w", err)
	}
	return nil
}
