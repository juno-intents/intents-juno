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
	"github.com/juno-intents/intents-juno/internal/policy"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

var (
	ErrInvalidConfig        = errors.New("withdrawcoordinator: invalid config")
	ErrRebroadcastExhausted = errors.New("withdrawcoordinator: rebroadcast attempts exhausted")
)

const (
	TxStatusConfirmed = "confirmed"
	TxStatusMempool   = "mempool"
	TxStatusMissing   = "missing"
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

	ExpiryPolicy policy.WithdrawExpiryConfig

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
		cfg:         cfg,
		store:       store,
		planner:     planner,
		signer:      signer,
		broadcaster: broadcaster,
		confirmer:   confirmer,
		txChecker:   txChecker,
		log:         log,
		batcher:     b,
		pendingIDs:  make(map[[32]byte]struct{}),
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

func (c *Coordinator) IngestWithdrawRequested(ctx context.Context, w withdraw.Withdrawal) error {
	_, _, err := c.store.UpsertRequested(ctx, w)
	return err
}

// Tick performs one coordinator iteration:
// - resume in-progress batches from durable state
// - claim new withdrawals and flush on maxItems/maxAge
func (c *Coordinator) Tick(ctx context.Context) error {
	if err := c.resume(ctx); err != nil {
		return err
	}

	// Claim new work to fill the in-progress batch.
	toClaim := c.cfg.MaxItems - c.batcher.Len()
	if toClaim < 0 {
		toClaim = 0
	}
	if toClaim > 0 {
		ws, err := c.store.ClaimUnbatched(ctx, c.cfg.Owner, c.cfg.ClaimTTL, toClaim)
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
				c.releasePending(batch.Items)
				if err := c.processNewBatch(ctx, batch); err != nil {
					return err
				}
			}
		}
	}

	if batch, ok := c.batcher.FlushDue(); ok {
		c.releasePending(batch.Items)
		if err := c.processNewBatch(ctx, batch); err != nil {
			return err
		}
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
	// Planned or signing => sign.
	for _, st := range []withdraw.BatchState{withdraw.BatchStatePlanned, withdraw.BatchStateSigning} {
		batches, err := c.store.ListBatchesByState(ctx, st)
		if err != nil {
			return err
		}
		for _, b := range batches {
			if err := c.signBatch(ctx, b.ID); err != nil {
				return err
			}
		}
	}

	// Signed => broadcast.
	signedBatches, err := c.store.ListBatchesByState(ctx, withdraw.BatchStateSigned)
	if err != nil {
		return err
	}
	for _, b := range signedBatches {
		if err := c.broadcastBatch(ctx, b.ID); err != nil {
			return err
		}
	}

	// Broadcasted => confirm.
	bcast, err := c.store.ListBatchesByState(ctx, withdraw.BatchStateBroadcasted)
	if err != nil {
		return err
	}
	for _, b := range bcast {
		if err := c.confirmBatch(ctx, b.ID); err != nil {
			return err
		}
	}
	return nil
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

	if err := c.store.CreatePlannedBatch(ctx, c.cfg.Owner, withdraw.Batch{
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
	b, err := c.store.GetBatch(ctx, batchID)
	if err != nil {
		return err
	}
	if b.State >= withdraw.BatchStateSigned {
		return nil
	}

	if err := c.store.MarkBatchSigning(ctx, batchID); err != nil {
		return err
	}

	c.log.Info("batch signing", "batch_id", hex.EncodeToString(batchID[:]))
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
		if dlqErr := c.maybeDLQWithdrawalBatch(ctx, b, "signing", "signing_failed", err.Error()); dlqErr != nil {
			return dlqErr
		}
		return err
	}
	if err := c.persistSignedTxArtifact(ctx, batchID, rawTx); err != nil {
		return err
	}
	if err := c.store.SetBatchSigned(ctx, batchID, rawTx); err != nil {
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
	if bytes.Equal(plan, b.TxPlan) {
		return false, nil
	}
	if err := c.store.ResetBatchSigning(ctx, b.ID, plan); err != nil {
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

	c.log.Info("batch broadcasting", "batch_id", hex.EncodeToString(batchID[:]))
	txid, err := c.broadcaster.Broadcast(ctx, b.SignedTx)
	if err != nil {
		return err
	}
	if err := c.store.SetBatchBroadcasted(ctx, batchID, txid); err != nil {
		return err
	}
	c.log.Info("batch broadcasted", "batch_id", hex.EncodeToString(batchID[:]), "juno_txid", txid)
	return nil
}

func (c *Coordinator) confirmBatch(ctx context.Context, batchID [32]byte) error {
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
	if err := c.ensureExpirySafety(ctx, b.WithdrawalIDs); err != nil {
		return err
	}
	c.log.Info("batch confirming", "batch_id", hex.EncodeToString(batchID[:]), "juno_txid", b.JunoTxID)
	if err := c.confirmer.WaitConfirmed(ctx, b.JunoTxID); err != nil {
		if errors.Is(err, ErrConfirmationPending) {
			return nil
		}
		if errors.Is(err, ErrConfirmationMissing) {
			// Double-spend prevention: verify the tx is truly missing from both
			// mempool and chain before rebroadcasting.
			if b.JunoTxID != "" {
				status, txErr := c.txChecker.TxStatus(ctx, b.JunoTxID)
				if txErr != nil {
					c.log.Error("tx status check failed, skipping rebroadcast", "txid", b.JunoTxID, "err", txErr)
					return nil
				}
				switch status {
				case TxStatusConfirmed:
					// Tx is confirmed on-chain; advance directly.
					return c.confirmPaidBatch(ctx, batchID, b.WithdrawalIDs, b.JunoTxID)
				case TxStatusMempool:
					// Tx is in mempool; wait — do not rebroadcast.
					return nil
				case TxStatusMissing:
					// Tx appears missing. Wait for 1 more block and re-check
					// to guard against propagation delay.
					if recheck, recheckErr := c.waitOneBlockAndRecheck(ctx, b.JunoTxID); recheckErr != nil {
						c.log.Error("wait-one-block recheck failed, skipping rebroadcast", "txid", b.JunoTxID, "err", recheckErr)
						return nil
					} else if recheck != TxStatusMissing {
						if recheck == TxStatusConfirmed {
							return c.confirmPaidBatch(ctx, batchID, b.WithdrawalIDs, b.JunoTxID)
						}
						// Back in mempool after the new block; keep waiting.
						return nil
					}
					// Still missing after 1 block — proceed with rebroadcast below.
				}
			}

			// Check max rebroadcast attempts.
			if c.cfg.MaxRebroadcastAttempts > 0 && int(b.RebroadcastAttempts) >= c.cfg.MaxRebroadcastAttempts {
				if err := c.maybeDLQWithdrawalBatch(ctx, b, "confirm", "rebroadcast_exhausted",
					fmt.Sprintf("exceeded max rebroadcast attempts (%d)", c.cfg.MaxRebroadcastAttempts)); err != nil {
					return err
				}
				return fmt.Errorf("%w: batch %x after %d attempts", ErrRebroadcastExhausted, b.ID[:8], b.RebroadcastAttempts)
			}

			now := c.cfg.Now().UTC()
			if !b.NextRebroadcastAt.IsZero() && now.Before(b.NextRebroadcastAt) {
				return nil
			}
			return c.replanAndRebroadcastBatch(ctx, b.ID)
		}
		return err
	}
	return c.confirmPaidBatch(ctx, batchID, b.WithdrawalIDs, b.JunoTxID)
}

func (c *Coordinator) confirmPaidBatch(ctx context.Context, batchID [32]byte, withdrawalIDs [][32]byte, junoTxID string) error {
	if c.paidMarker == nil {
		return fmt.Errorf("%w: nil paid marker", ErrInvalidConfig)
	}
	if err := c.paidMarker.MarkPaid(ctx, withdrawalIDs); err != nil {
		return err
	}
	if err := c.store.SetBatchConfirmed(ctx, batchID); err != nil {
		return err
	}
	c.log.Info("batch confirmed", "batch_id", hex.EncodeToString(batchID[:]), "juno_txid", junoTxID)
	return nil
}

// waitOneBlockAndRecheck waits for the Juno chain to advance by at least one
// block, then re-checks the tx status. This prevents rebroadcasting a tx that
// was recently submitted but hasn't propagated to the mempool yet.
func (c *Coordinator) waitOneBlockAndRecheck(ctx context.Context, txid string) (string, error) {
	startHeight, err := c.txChecker.TipHeight(ctx)
	if err != nil {
		return "", fmt.Errorf("get tip height: %w", err)
	}

	targetHeight := startHeight + 1
	pollInterval := 2 * time.Second
	timeout := 5 * time.Minute

	deadline := c.cfg.Now().Add(timeout)
	for {
		if !c.cfg.Now().Before(deadline) {
			return "", fmt.Errorf("timed out waiting for block %d (stuck at %d)", targetHeight, startHeight)
		}
		t := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return "", ctx.Err()
		case <-t.C:
		}
		h, err := c.txChecker.TipHeight(ctx)
		if err != nil {
			c.log.Warn("tip height poll failed, retrying", "err", err)
			continue
		}
		if h >= targetHeight {
			break
		}
	}

	return c.txChecker.TxStatus(ctx, txid)
}

func (c *Coordinator) replanAndRebroadcastBatch(ctx context.Context, batchID [32]byte) error {
	b, err := c.store.GetBatch(ctx, batchID)
	if err != nil {
		return err
	}
	if b.State != withdraw.BatchStateBroadcasted {
		return nil
	}

	withdrawals := make([]withdraw.Withdrawal, 0, len(b.WithdrawalIDs))
	for _, wid := range b.WithdrawalIDs {
		w, err := c.store.GetWithdrawal(ctx, wid)
		if err != nil {
			return err
		}
		withdrawals = append(withdrawals, w)
	}

	plan, err := c.planner.Plan(ctx, b.ID, withdrawals)
	if err != nil {
		return err
	}
	if err := c.store.ResetBatchPlanned(ctx, b.ID, plan); err != nil {
		if !errors.Is(err, withdraw.ErrInvalidTransition) {
			return err
		}
		b2, err2 := c.store.GetBatch(ctx, b.ID)
		if err2 != nil {
			return err2
		}
		// Another worker progressed the batch.
		if b2.State != withdraw.BatchStateBroadcasted {
			return nil
		}
		return err
	}
	c.log.Info("batch replanned for rebroadcast", "batch_id", hex.EncodeToString(batchID[:]), "attempt", b.RebroadcastAttempts+1)
	if err := c.persistTxPlanArtifact(ctx, b.ID, plan); err != nil {
		return err
	}

	if err := c.signBatch(ctx, b.ID); err != nil {
		return err
	}
	if err := c.broadcastBatch(ctx, b.ID); err != nil {
		return err
	}

	now := c.cfg.Now().UTC()
	nextAttempts := b.RebroadcastAttempts + 1
	nextAt := now.Add(c.rebroadcastBackoff(nextAttempts))
	return c.store.SetBatchRebroadcastBackoff(ctx, b.ID, nextAttempts, nextAt)
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
