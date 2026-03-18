package withdrawcoordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/juno-intents/intents-juno/internal/batching"
	"github.com/juno-intents/intents-juno/internal/blobstore"
	"github.com/juno-intents/intents-juno/internal/dlq"
	"github.com/juno-intents/intents-juno/internal/leases"
	"github.com/juno-intents/intents-juno/internal/policy"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

var (
	ErrInvalidConfig        = errors.New("withdrawcoordinator: invalid config")
	ErrRebroadcastExhausted = errors.New("withdrawcoordinator: rebroadcast attempts exhausted")
	ErrLeadershipLost       = errors.New("withdrawcoordinator: leadership lost")
)

const (
	TxStatusConfirmed = "confirmed"
	TxStatusMempool   = "mempool"
	TxStatusMissing   = "missing"

	batchFailureDLQThreshold      = 3
	markPaidFailureOpenThreshold  = 3
)

type Planner interface {
	Plan(ctx context.Context, batchID [32]byte, withdrawals []withdraw.Withdrawal) ([]byte, error)
}

type Signer interface {
	// Sign must be idempotent for a given signingSessionID.
	Sign(ctx context.Context, signingSessionID [32]byte, txPlan []byte) ([]byte, error)
}

type Broadcaster interface {
	Broadcast(ctx context.Context, rawTx []byte) (string, error)
}

type Confirmer interface {
	WaitConfirmed(ctx context.Context, txid string) error
}

// TxChecker checks the status of a Juno transaction (confirmed, mempool, missing)
// and provides chain-tip height for wait-one-block logic.
type TxChecker interface {
	TxStatus(ctx context.Context, txid string) (string, error)
	TipHeight(ctx context.Context) (uint64, error)
}

// ExpiryExtender optionally extends withdrawal expiries on Base before broadcasting a Juno payout.
//
// Implementations must be idempotent.
type ExpiryExtender interface {
	Extend(ctx context.Context, ids [][32]byte, newExpiry time.Time) error
}

// PaidMarker marks Base-side withdrawals paid/irrevocable after Juno confirmation.
//
// Implementations must be idempotent so retries are safe if the durable store write fails.
type PaidMarker interface {
	MarkPaid(ctx context.Context, ids [][32]byte) error
}

type Config struct {
	Owner string

	MaxItems int
	MaxAge   time.Duration
	ClaimTTL time.Duration

	RebroadcastBaseDelay   time.Duration
	RebroadcastMaxDelay    time.Duration
	MaxRebroadcastAttempts int // default 5; 0 = unlimited

	// DLQStore is an optional dead-letter queue store. If nil, DLQ insertion is skipped.
	DLQStore dlq.Store

	ExpiryPolicy     policy.WithdrawExpiryConfig
	LeaderLeaseStore leases.Store

	Now func() time.Time
}

type Coordinator struct {
	cfg Config

	store       withdraw.Store
	planner     Planner
	signer      Signer
	broadcaster Broadcaster
	confirmer   Confirmer
	txChecker   TxChecker
	extender    ExpiryExtender
	paidMarker  PaidMarker
	blobStore   blobstore.Store

	log *slog.Logger

	batcher *batching.Batcher[withdraw.Withdrawal]
	// pendingIDs tracks withdrawals currently buffered in the in-memory batcher.
	// This prevents duplicate re-claims (after claim TTL expiry) from being
	// appended multiple times before a flush occurs.
	pendingIDs map[[32]byte]struct{}

	leaderLeaseStore leases.Store
	currentLeader    leases.Lease

	markPaidFailureStreak int
	markPaidCircuitOpen   bool
}

func New(cfg Config, store withdraw.Store, planner Planner, signer Signer, broadcaster Broadcaster, confirmer Confirmer, txChecker TxChecker, log *slog.Logger) (*Coordinator, error) {
	if store == nil || planner == nil || signer == nil || broadcaster == nil || confirmer == nil || txChecker == nil {
		return nil, fmt.Errorf("%w: nil dependency", ErrInvalidConfig)
	}
	if cfg.Owner == "" {
		return nil, fmt.Errorf("%w: missing owner", ErrInvalidConfig)
	}
	if cfg.MaxItems <= 0 {
		return nil, fmt.Errorf("%w: MaxItems must be > 0", ErrInvalidConfig)
	}
	if cfg.MaxAge <= 0 {
		return nil, fmt.Errorf("%w: MaxAge must be > 0", ErrInvalidConfig)
	}
	if cfg.ClaimTTL <= 0 {
		return nil, fmt.Errorf("%w: ClaimTTL must be > 0", ErrInvalidConfig)
	}
	if cfg.MaxRebroadcastAttempts == 0 {
		cfg.MaxRebroadcastAttempts = 5
	}
	if cfg.RebroadcastBaseDelay == 0 {
		cfg.RebroadcastBaseDelay = 30 * time.Second
	}
	if cfg.RebroadcastMaxDelay == 0 {
		cfg.RebroadcastMaxDelay = 10 * time.Minute
	}
	if cfg.RebroadcastBaseDelay <= 0 {
		return nil, fmt.Errorf("%w: RebroadcastBaseDelay must be > 0", ErrInvalidConfig)
	}
	if cfg.RebroadcastMaxDelay <= 0 || cfg.RebroadcastMaxDelay < cfg.RebroadcastBaseDelay {
		return nil, fmt.Errorf("%w: RebroadcastMaxDelay must be >= RebroadcastBaseDelay", ErrInvalidConfig)
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
		cfg.Now = nowFn
	}

	if cfg.ExpiryPolicy.SafetyMargin == 0 {
		cfg.ExpiryPolicy.SafetyMargin = policy.DefaultWithdrawExpirySafetyMargin
	}
	if cfg.ExpiryPolicy.MaxExtension == 0 {
		cfg.ExpiryPolicy.MaxExtension = policy.DefaultWithdrawExpirySafetyMargin * 2
	}
	if cfg.ExpiryPolicy.MaxBatch == 0 {
		cfg.ExpiryPolicy.MaxBatch = policy.DefaultMaxExtendBatch
	}

	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	b, err := batching.New[withdraw.Withdrawal](batching.Config{
		MaxItems: cfg.MaxItems,
		MaxAge:   cfg.MaxAge,
		Now:      nowFn,
	})
	if err != nil {
		return nil, err
	}

	return &Coordinator{
		cfg:              cfg,
		store:            store,
		planner:          planner,
		signer:           signer,
		broadcaster:      broadcaster,
		confirmer:        confirmer,
		txChecker:        txChecker,
		log:              log,
		batcher:          b,
		pendingIDs:       make(map[[32]byte]struct{}),
		leaderLeaseStore: cfg.LeaderLeaseStore,
	}, nil
}

// WithExpiryExtender configures an optional Base expiry extension hook.
func (c *Coordinator) WithExpiryExtender(ext ExpiryExtender) *Coordinator {
	c.extender = ext
	return c
}

// WithPaidMarker configures the Base-side mark-paid hook required before durable paid status is written.
func (c *Coordinator) WithPaidMarker(marker PaidMarker) *Coordinator {
	c.paidMarker = marker
	return c
}

// WithBlobStore configures optional artifact persistence for tx plans and signed tx bytes.
func (c *Coordinator) WithBlobStore(store blobstore.Store) *Coordinator {
	c.blobStore = store
	return c
}

func (c *Coordinator) SetLeaderLease(lease leases.Lease) {
	c.currentLeader = lease
}

func (c *Coordinator) ClearLeaderLease() {
	c.currentLeader = leases.Lease{}
}

func (c *Coordinator) storeFence() withdraw.Fence {
	version := c.currentLeader.Version
	if version <= 0 {
		version = 1
	}
	return withdraw.Fence{
		Owner:        c.cfg.Owner,
		LeaseVersion: version,
	}
}

func (c *Coordinator) assertLeadership(ctx context.Context) error {
	if c.leaderLeaseStore == nil {
		return nil
	}
	if c.currentLeader.Name == "" || c.currentLeader.Owner == "" || c.currentLeader.Version <= 0 {
		return fmt.Errorf("%w: missing current leader lease", ErrInvalidConfig)
	}
	lease, err := c.leaderLeaseStore.Get(ctx, c.currentLeader.Name)
	if err != nil {
		if errors.Is(err, leases.ErrNotFound) {
			return ErrLeadershipLost
		}
		return err
	}
	if lease.Owner != c.currentLeader.Owner || lease.Version != c.currentLeader.Version {
		return ErrLeadershipLost
	}
	if !lease.ExpiresAt.After(c.cfg.Now()) {
		return ErrLeadershipLost
	}
	return nil
}

func (c *Coordinator) IngestWithdrawRequested(ctx context.Context, w withdraw.Withdrawal) error {
	_, _, err := c.store.UpsertRequested(ctx, w)
	return err
}

// Tick performs one coordinator iteration:
// - resume in-progress batches from durable state
// - claim new withdrawals and flush on maxItems/maxAge
func (c *Coordinator) Tick(ctx context.Context) error {
	if err := c.assertLeadership(ctx); err != nil {
		return err
	}

	var tickErr error
	if err := c.resume(ctx); err != nil {
		tickErr = err
	}

	// Claim new work to fill the in-progress batch.
	toClaim := c.cfg.MaxItems - c.batcher.Len()
	if toClaim < 0 {
		toClaim = 0
	}
	if !c.markPaidCircuitOpen && toClaim > 0 {
		if err := c.assertLeadership(ctx); err != nil {
			return err
		}
		ws, err := c.store.ClaimUnbatched(ctx, c.storeFence(), c.cfg.ClaimTTL, toClaim)
		if err != nil {
			return err
		}
		for _, w := range ws {
			if _, exists := c.pendingIDs[w.ID]; exists {
				continue
			}
			c.pendingIDs[w.ID] = struct{}{}
			batch, ok := c.batcher.Add(w.ID, w)
			if ok {
				if err := c.assertLeadership(ctx); err != nil {
					return errors.Join(tickErr, err)
				}
				c.releasePending(batch.Items)
				if err := c.processNewBatch(ctx, batch); err != nil {
					return errors.Join(tickErr, err)
				}
			}
		}
	}

	if !c.markPaidCircuitOpen {
		if batch, ok := c.batcher.FlushDue(); ok {
			if err := c.assertLeadership(ctx); err != nil {
				return errors.Join(tickErr, err)
			}
			c.releasePending(batch.Items)
			if err := c.processNewBatch(ctx, batch); err != nil {
				return errors.Join(tickErr, err)
			}
		}
	}

	if tickErr != nil {
		return tickErr
	}
	return c.resume(ctx)
}

func (c *Coordinator) releasePending(items []batching.Item[withdraw.Withdrawal]) {
	if len(items) == 0 || c.pendingIDs == nil {
		return
	}
	for _, it := range items {
		delete(c.pendingIDs, it.ID)
	}
}

func (c *Coordinator) resume(ctx context.Context) error {
	var resumeErr error
	if !c.markPaidCircuitOpen {
		for _, st := range []withdraw.BatchState{withdraw.BatchStatePlanned, withdraw.BatchStateSigning} {
			batches, err := c.store.ListBatchesByState(ctx, st)
			if err != nil {
				return err
			}
			for _, b := range batches {
				if err := c.assertLeadership(ctx); err != nil {
					return err
				}
				if err := c.processBatchError(ctx, b.ID, "signing", c.signBatch(ctx, b.ID)); err != nil && resumeErr == nil {
					resumeErr = err
				}
			}
		}

		signedBatches, err := c.store.ListBatchesByState(ctx, withdraw.BatchStateSigned)
		if err != nil {
			return err
		}
		for _, b := range signedBatches {
			if err := c.assertLeadership(ctx); err != nil {
				return err
			}
			if err := c.processBatchError(ctx, b.ID, "broadcast", c.broadcastBatch(ctx, b.ID)); err != nil && resumeErr == nil {
				resumeErr = err
			}
		}
	}

	bcast, err := c.store.ListBatchesByState(ctx, withdraw.BatchStateBroadcasted)
	if err != nil {
		return err
	}
	for _, b := range bcast {
		if err := c.assertLeadership(ctx); err != nil {
			return err
		}
		if err := c.processBatchError(ctx, b.ID, "confirm", c.confirmBatch(ctx, b.ID)); err != nil && resumeErr == nil {
			resumeErr = err
		}
	}
	return resumeErr
}

func (c *Coordinator) processNewBatch(ctx context.Context, batch batching.Batch[withdraw.Withdrawal]) error {
	if len(batch.Items) == 0 {
		return nil
	}

	withdrawals := make([]withdraw.Withdrawal, 0, len(batch.Items))
	ids := make([][32]byte, 0, len(batch.Items))
	for _, it := range batch.Items {
		withdrawals = append(withdrawals, it.Val)
		ids = append(ids, it.ID)
	}

	batchID := batching.WithdrawalBatchIDV1(ids)
	plan, err := c.planner.Plan(ctx, batchID, withdrawals)
	if err != nil {
		return err
	}
	if err := c.assertLeadership(ctx); err != nil {
		return err
	}

	if err := c.store.CreatePlannedBatch(ctx, c.storeFence(), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: ids,
		State:         withdraw.BatchStatePlanned,
		TxPlan:        plan,
	}); err != nil {
		return err
	}
	c.log.Info("batch planned", "batch_id", hex.EncodeToString(batchID[:]), "withdrawals", len(batch.Items))
	if err := c.persistTxPlanArtifact(ctx, batchID, plan); err != nil {
		return err
	}

	// Continue immediately; resume() will do the rest too, but this avoids an extra cycle.
	if err := c.signBatch(ctx, batchID); err != nil {
		return err
	}
	if err := c.broadcastBatch(ctx, batchID); err != nil {
		return err
	}
	return c.confirmBatch(ctx, batchID)
}

func (c *Coordinator) signBatch(ctx context.Context, batchID [32]byte) error {
	return c.signBatchWithRetry(ctx, batchID, true)
}

func (c *Coordinator) signBatchWithRetry(ctx context.Context, batchID [32]byte, allowReplan bool) error {
	fence := c.storeFence()
	if err := c.store.AdoptBatch(ctx, batchID, fence); err != nil {
		return err
	}
	b, err := c.store.GetBatch(ctx, batchID)
	if err != nil {
		return err
	}
	if b.State >= withdraw.BatchStateSigned {
		return nil
	}

	if err := c.store.MarkBatchSigning(ctx, batchID, fence); err != nil {
		return err
	}

	c.log.Info("batch signing", "batch_id", hex.EncodeToString(batchID[:]))
	if err := c.assertLeadership(ctx); err != nil {
		return err
	}
	rawTx, err := c.signer.Sign(ctx, signingSessionIDV1(batchID, b.TxPlan), b.TxPlan)
	if err != nil {
		if allowReplan {
			replanned, replanErr := c.maybeReplanBatchAfterSigningFailure(ctx, b, err)
			if replanErr != nil {
				return replanErr
			}
			if replanned {
				return c.signBatchWithRetry(ctx, batchID, false)
			}
		}
		return err
	}
	if err := c.assertLeadership(ctx); err != nil {
		return err
	}
	if err := c.persistSignedTxArtifact(ctx, batchID, rawTx); err != nil {
		return err
	}
	if err := c.store.SetBatchSigned(ctx, batchID, fence, rawTx); err != nil {
		return err
	}
	c.log.Info("batch signed", "batch_id", hex.EncodeToString(batchID[:]), "raw_tx_len", len(rawTx))
	return nil
}

func (c *Coordinator) maybeReplanBatchAfterSigningFailure(ctx context.Context, b withdraw.Batch, signErr error) (bool, error) {
	if !isStaleSigningTxPlanError(signErr) {
		return false, nil
	}

	withdrawals := make([]withdraw.Withdrawal, 0, len(b.WithdrawalIDs))
	for _, wid := range b.WithdrawalIDs {
		w, err := c.store.GetWithdrawal(ctx, wid)
		if err != nil {
			return false, err
		}
		withdrawals = append(withdrawals, w)
	}

	plan, err := c.planner.Plan(ctx, b.ID, withdrawals)
	if err != nil {
		return false, err
	}
	if err := c.assertLeadership(ctx); err != nil {
		return false, err
	}
	if bytes.Equal(plan, b.TxPlan) {
		return false, nil
	}
	if err := c.store.ResetBatchSigning(ctx, b.ID, c.storeFence(), plan); err != nil {
		if !errors.Is(err, withdraw.ErrInvalidTransition) {
			return false, err
		}
		b2, err2 := c.store.GetBatch(ctx, b.ID)
		if err2 != nil {
			return false, err2
		}
		if b2.State != withdraw.BatchStateSigning {
			return false, nil
		}
		return false, err
	}
	c.log.Info(
		"batch replanned after signing failure",
		"batch_id", hex.EncodeToString(b.ID[:]),
		"error", signErr.Error(),
	)
	if err := c.persistTxPlanArtifact(ctx, b.ID, plan); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Coordinator) broadcastBatch(ctx context.Context, batchID [32]byte) error {
	return c.broadcastBatchWithRetry(ctx, batchID, true)
}

func (c *Coordinator) broadcastBatchWithRetry(ctx context.Context, batchID [32]byte, allowReplan bool) error {
	fence := c.storeFence()
	if err := c.store.AdoptBatch(ctx, batchID, fence); err != nil {
		return err
	}
	b, err := c.store.GetBatch(ctx, batchID)
	if err != nil {
		return err
	}
	if b.State >= withdraw.BatchStateBroadcasted {
		return nil
	}
	if b.State < withdraw.BatchStateSigned {
		return withdraw.ErrInvalidTransition
	}

	if err := c.ensureExpirySafety(ctx, b.WithdrawalIDs); err != nil {
		return err
	}
	if err := c.store.MarkBatchBroadcastLocked(ctx, batchID, fence); err != nil {
		return err
	}

	c.log.Info("batch broadcasting", "batch_id", hex.EncodeToString(batchID[:]))
	if err := c.assertLeadership(ctx); err != nil {
		return err
	}
	txid, err := c.broadcaster.Broadcast(ctx, b.SignedTx)
	if err != nil {
		return err
	}
	if err := c.assertLeadership(ctx); err != nil {
		return err
	}
	if err := c.store.SetBatchBroadcasted(ctx, batchID, fence, txid); err != nil {
		return err
	}
	c.log.Info("batch broadcasted", "batch_id", hex.EncodeToString(batchID[:]), "juno_txid", txid)
	return nil
}

func (c *Coordinator) confirmBatch(ctx context.Context, batchID [32]byte) error {
	fence := c.storeFence()
	if err := c.store.AdoptBatch(ctx, batchID, fence); err != nil {
		return err
	}
	b, err := c.store.GetBatch(ctx, batchID)
	if err != nil {
		return err
	}
	if b.State == withdraw.BatchStateConfirmed {
		return nil
	}
	if b.State < withdraw.BatchStateBroadcasted {
		return withdraw.ErrInvalidTransition
	}
	if !b.JunoConfirmedAt.IsZero() {
		return c.confirmPaidBatch(ctx, batchID, b.WithdrawalIDs, b.JunoTxID)
	}
	c.log.Info("batch confirming", "batch_id", hex.EncodeToString(batchID[:]), "juno_txid", b.JunoTxID)
	if err := c.assertLeadership(ctx); err != nil {
		return err
	}
	if err := c.confirmer.WaitConfirmed(ctx, b.JunoTxID); err != nil {
		if errors.Is(err, ErrConfirmationPending) {
			return nil
		}
		if errors.Is(err, ErrConfirmationMissing) {
			if b.JunoTxID != "" {
				status, txErr := c.txChecker.TxStatus(ctx, b.JunoTxID)
				if txErr != nil {
					c.log.Error("tx status check failed, skipping rebroadcast", "txid", b.JunoTxID, "err", txErr)
					return nil
				}
				switch status {
				case TxStatusConfirmed:
					if err := c.store.MarkBatchJunoConfirmed(ctx, batchID, fence); err != nil {
						return err
					}
					return c.confirmPaidBatch(ctx, batchID, b.WithdrawalIDs, b.JunoTxID)
				case TxStatusMempool:
					return nil
				case TxStatusMissing:
				}
			}

			if c.cfg.MaxRebroadcastAttempts > 0 && int(b.RebroadcastAttempts) >= c.cfg.MaxRebroadcastAttempts {
				return fmt.Errorf("%w: batch %x after %d attempts", ErrRebroadcastExhausted, b.ID[:8], b.RebroadcastAttempts)
			}

			now := c.cfg.Now().UTC()
			if !b.NextRebroadcastAt.IsZero() && now.Before(b.NextRebroadcastAt) {
				return nil
			}
			attempts := b.RebroadcastAttempts
			if attempts == 0 {
				attempts = 1
			}
			nextAt := now.Add(c.rebroadcastBackoff(attempts))
			if err := c.store.SetBatchRebroadcastBackoff(ctx, b.ID, fence, b.RebroadcastAttempts, nextAt); err != nil {
				return err
			}
			return c.rebroadcastSignedBatch(ctx, b.ID)
		}
		return err
	}
	if err := c.store.MarkBatchJunoConfirmed(ctx, batchID, fence); err != nil {
		return err
	}
	return c.confirmPaidBatch(ctx, batchID, b.WithdrawalIDs, b.JunoTxID)
}

func (c *Coordinator) confirmPaidBatch(ctx context.Context, batchID [32]byte, withdrawalIDs [][32]byte, junoTxID string) error {
	fence := c.storeFence()
	if err := c.assertLeadership(ctx); err != nil {
		return err
	}
	if c.paidMarker == nil {
		return fmt.Errorf("%w: nil paid marker", ErrInvalidConfig)
	}
	if err := c.paidMarker.MarkPaid(ctx, withdrawalIDs); err != nil {
		if _, ferr := c.store.RecordBatchMarkPaidFailure(ctx, batchID, fence, err.Error()); ferr != nil {
			return ferr
		}
		c.markPaidFailureStreak++
		if c.markPaidFailureStreak >= markPaidFailureOpenThreshold {
			c.markPaidCircuitOpen = true
		}
		return err
	}
	c.markPaidFailureStreak = 0
	c.markPaidCircuitOpen = false
	if err := c.store.ResetBatchMarkPaidFailures(ctx, batchID, fence); err != nil {
		return err
	}
	if err := c.store.SetBatchConfirmed(ctx, batchID, fence); err != nil {
		return err
	}
	c.log.Info("batch confirmed", "batch_id", hex.EncodeToString(batchID[:]), "juno_txid", junoTxID)
	return nil
}

func (c *Coordinator) rebroadcastSignedBatch(ctx context.Context, batchID [32]byte) error {
	fence := c.storeFence()
	if err := c.store.AdoptBatch(ctx, batchID, fence); err != nil {
		return err
	}
	b, err := c.store.GetBatch(ctx, batchID)
	if err != nil {
		return err
	}
	if b.State != withdraw.BatchStateBroadcasted {
		return nil
	}
	if len(b.SignedTx) == 0 {
		return fmt.Errorf("withdrawcoordinator: missing signed tx for rebroadcast batch %x", b.ID[:8])
	}

	c.log.Info("rebroadcasting existing signed batch", "batch_id", hex.EncodeToString(batchID[:]), "attempt", b.RebroadcastAttempts+1)
	if err := c.assertLeadership(ctx); err != nil {
		return err
	}
	txid, err := c.broadcaster.Broadcast(ctx, b.SignedTx)
	if err != nil {
		return err
	}
	if txid == "" {
		return fmt.Errorf("withdrawcoordinator: rebroadcast returned empty txid")
	}
	if b.JunoTxID != "" && txid != b.JunoTxID {
		statuses := make(map[string]string, 2)
		for _, candidate := range []string{b.JunoTxID, txid} {
			if candidate == "" {
				continue
			}
			status, statusErr := c.txChecker.TxStatus(ctx, candidate)
			if statusErr != nil {
				return statusErr
			}
			statuses[candidate] = status
		}
		switch {
		case statuses[b.JunoTxID] == TxStatusConfirmed:
			if err := c.store.MarkBatchJunoConfirmed(ctx, batchID, fence); err != nil {
				return err
			}
			return c.confirmPaidBatch(ctx, batchID, b.WithdrawalIDs, b.JunoTxID)
		case statuses[txid] == TxStatusConfirmed:
			if err := c.store.MarkBatchJunoConfirmed(ctx, batchID, fence); err != nil {
				return err
			}
			return c.confirmPaidBatch(ctx, batchID, b.WithdrawalIDs, txid)
		default:
			return fmt.Errorf("withdrawcoordinator: rebroadcast txid mismatch: got %s want %s", txid, b.JunoTxID)
		}
	}
	if err := c.assertLeadership(ctx); err != nil {
		return err
	}
	if err := c.store.SetBatchBroadcasted(ctx, b.ID, fence, txid); err != nil {
		return err
	}

	now := c.cfg.Now().UTC()
	nextAttempts := b.RebroadcastAttempts + 1
	nextAt := now.Add(c.rebroadcastBackoff(nextAttempts))
	return c.store.SetBatchRebroadcastBackoff(ctx, b.ID, fence, nextAttempts, nextAt)
}

func (c *Coordinator) ensureExpirySafety(ctx context.Context, withdrawalIDs [][32]byte) error {
	if c.cfg.ExpiryPolicy.SafetyMargin <= 0 {
		return nil
	}

	now := c.cfg.Now()

	// Load expiries from durable withdrawal records.
	ws := make([]policy.Withdrawal, 0, len(withdrawalIDs))
	for _, id := range withdrawalIDs {
		w, err := c.store.GetWithdrawal(ctx, id)
		if err != nil {
			return err
		}
		ws = append(ws, policy.Withdrawal{ID: w.ID, Expiry: w.Expiry})
	}

	plans, err := policy.PlanExtendWithdrawExpiryBatches(now, ws, c.cfg.ExpiryPolicy)
	if err != nil {
		return err
	}
	if len(plans) == 0 {
		return nil
	}

	if c.extender == nil {
		return fmt.Errorf("withdrawcoordinator: expiry extension required but no extender configured")
	}

	for _, p := range plans {
		if err := c.assertLeadership(ctx); err != nil {
			return err
		}
		if err := c.extender.Extend(ctx, p.IDs, p.NewExpiry); err != nil {
			return err
		}
	}
	return nil
}

// signingSessionIDV1 binds signing idempotency to both logical batch id and txPlan bytes.
// This allows safe re-planning/re-signing when a broadcasted tx disappears.
func signingSessionIDV1(batchID [32]byte, txPlan []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("withdraw-sign-session-v1"))
	_, _ = h.Write(batchID[:])
	_, _ = h.Write(txPlan)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func isStaleSigningTxPlanError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "note_decrypt_failed")
}

func isStaleBroadcastTxError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "tx-expiring-soon") ||
		strings.Contains(lower, "expiryheight") ||
		strings.Contains(lower, "transaction expired")
}

func (c *Coordinator) rebroadcastBackoff(attempts uint32) time.Duration {
	if attempts <= 1 {
		return c.cfg.RebroadcastBaseDelay
	}

	backoff := c.cfg.RebroadcastBaseDelay
	for i := uint32(1); i < attempts; i++ {
		if backoff >= c.cfg.RebroadcastMaxDelay {
			return c.cfg.RebroadcastMaxDelay
		}
		if backoff > c.cfg.RebroadcastMaxDelay/2 {
			return c.cfg.RebroadcastMaxDelay
		}
		backoff *= 2
	}
	if backoff > c.cfg.RebroadcastMaxDelay {
		return c.cfg.RebroadcastMaxDelay
	}
	return backoff
}

func txPlanArtifactKey(batchID [32]byte) string {
	return "withdrawals/batches/" + hex.EncodeToString(batchID[:]) + "/txplan.json"
}

func signedTxArtifactKey(batchID [32]byte) string {
	return "withdrawals/batches/" + hex.EncodeToString(batchID[:]) + "/signed.tx"
}

func (c *Coordinator) processBatchError(ctx context.Context, batchID [32]byte, stage string, batchErr error) error {
	if batchErr == nil {
		return nil
	}
	if errors.Is(batchErr, ErrLeadershipLost) {
		return batchErr
	}

	fence := c.storeFence()
	errorCode := batchErrorCode(stage, batchErr)
	updated, err := c.store.RecordBatchFailure(ctx, batchID, fence, stage, errorCode, batchErr.Error())
	if err != nil {
		return err
	}

	terminal := updated.FailureCount >= batchFailureDLQThreshold ||
		errors.Is(batchErr, ErrRebroadcastExhausted) ||
		errorCode == "rebroadcast_txid_mismatch"
	if !terminal {
		return batchErr
	}
	if err := c.maybeDLQWithdrawalBatch(ctx, updated, stage, errorCode, batchErr.Error()); err != nil {
		return err
	}
	if err := c.store.MarkBatchDLQ(ctx, batchID, fence); err != nil {
		return err
	}
	return batchErr
}

func batchErrorCode(stage string, err error) string {
	switch {
	case errors.Is(err, ErrRebroadcastExhausted):
		return "rebroadcast_exhausted"
	case strings.Contains(strings.ToLower(err.Error()), "txid mismatch"):
		return "rebroadcast_txid_mismatch"
	case stage == "signing":
		return "signing_failed"
	case stage == "broadcast":
		return "broadcast_failed"
	case stage == "confirm":
		return "confirm_failed"
	default:
		return "batch_failed"
	}
}

func (c *Coordinator) persistTxPlanArtifact(ctx context.Context, batchID [32]byte, txPlan []byte) error {
	if c.blobStore == nil {
		return nil
	}
	if err := c.blobStore.Put(ctx, txPlanArtifactKey(batchID), txPlan, blobstore.PutOptions{
		ContentType: "application/json",
		Metadata: map[string]string{
			"artifact-type": "withdraw-txplan",
			"batch-id":      hex.EncodeToString(batchID[:]),
		},
	}); err != nil {
		return fmt.Errorf("withdrawcoordinator: persist tx plan artifact: %w", err)
	}
	return nil
}

// maybeDLQWithdrawalBatch inserts a withdrawal batch into the dead-letter queue.
// If DLQStore is nil, this is a no-op.
func (c *Coordinator) maybeDLQWithdrawalBatch(ctx context.Context, b withdraw.Batch, failureStage, errorCode, errorMessage string) error {
	if c.cfg.DLQStore == nil {
		return nil
	}

	rec := dlq.WithdrawalBatchDLQRecord{
		BatchID:             b.ID,
		WithdrawalIDs:       b.WithdrawalIDs,
		ItemsCount:          len(b.WithdrawalIDs),
		State:               int16(b.State),
		FailureStage:        failureStage,
		ErrorCode:           errorCode,
		ErrorMessage:        errorMessage,
		RebroadcastAttempts: int(b.RebroadcastAttempts),
		JunoTxID:            b.JunoTxID,
	}

	if err := c.cfg.DLQStore.InsertWithdrawalBatchDLQ(ctx, rec); err != nil {
		c.log.Error("withdrawcoordinator: failed to insert into DLQ",
			"batch_id", fmt.Sprintf("%x", b.ID[:8]),
			"failure_stage", failureStage,
			"err", err,
		)
		return fmt.Errorf("withdrawcoordinator: insert withdrawal batch DLQ: %w", err)
	}
	c.log.Info("withdrawcoordinator: inserted batch into DLQ",
		"batch_id", fmt.Sprintf("%x", b.ID[:8]),
		"failure_stage", failureStage,
		"items", len(b.WithdrawalIDs),
	)
	return nil
}

func (c *Coordinator) persistSignedTxArtifact(ctx context.Context, batchID [32]byte, signedTx []byte) error {
	if c.blobStore == nil {
		return nil
	}
	if err := c.blobStore.Put(ctx, signedTxArtifactKey(batchID), signedTx, blobstore.PutOptions{
		ContentType: "application/octet-stream",
		Metadata: map[string]string{
			"artifact-type": "withdraw-signed-tx",
			"batch-id":      hex.EncodeToString(batchID[:]),
		},
	}); err != nil {
		return fmt.Errorf("withdrawcoordinator: persist signed tx artifact: %w", err)
	}
	return nil
}
