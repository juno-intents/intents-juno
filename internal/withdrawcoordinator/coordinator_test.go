package withdrawcoordinator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/juno-intents/intents-juno/internal/batching"
	"github.com/juno-intents/intents-juno/internal/blobstore"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

type stubPlanner struct {
	calls int
}

func (p *stubPlanner) Plan(_ context.Context, batchID [32]byte, withdrawals []withdraw.Withdrawal) ([]byte, error) {
	_ = batchID
	_ = withdrawals
	p.calls++
	return []byte(`{"v":1}`), nil
}

type stubSigner struct {
	calls int
	ids   [][32]byte
}

func (s *stubSigner) Sign(_ context.Context, signingSessionID [32]byte, txPlan []byte) ([]byte, error) {
	_ = txPlan
	s.calls++
	s.ids = append(s.ids, signingSessionID)
	return []byte{0x01}, nil
}

type stubBroadcaster struct {
	calls int
}

func (b *stubBroadcaster) Broadcast(_ context.Context, rawTx []byte) (string, error) {
	_ = rawTx
	b.calls++
	return "tx1", nil
}

type stubConfirmer struct {
	calls int
	errs  []error
}

func (c *stubConfirmer) WaitConfirmed(_ context.Context, txid string) error {
	_ = txid
	c.calls++
	if c.calls <= len(c.errs) {
		return c.errs[c.calls-1]
	}
	return nil
}

type recordingBlobPut struct {
	key     string
	payload []byte
	opts    blobstore.PutOptions
}

type recordingBlobStore struct {
	puts   []recordingBlobPut
	putErr error
}

func (s *recordingBlobStore) Put(_ context.Context, key string, payload []byte, opts blobstore.PutOptions) error {
	if s.putErr != nil {
		return s.putErr
	}
	s.puts = append(s.puts, recordingBlobPut{
		key:     key,
		payload: append([]byte(nil), payload...),
		opts:    opts,
	})
	return nil
}

func (s *recordingBlobStore) Get(context.Context, string) (blobstore.Object, error) {
	return blobstore.Object{}, errors.New("unexpected Get")
}

func (s *recordingBlobStore) Delete(context.Context, string) error { return nil }

func (s *recordingBlobStore) Exists(context.Context, string) (bool, error) { return false, nil }

func seq32(start byte) (out [32]byte) {
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
}

func TestCoordinator_BuildsSignsBroadcastsAndConfirms_OnMaxItems(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	planner := &stubPlanner{}
	signer := &stubSigner{}
	broadcaster := &stubBroadcaster{}
	confirmer := &stubConfirmer{}

	c, err := New(Config{
		Owner:    "a",
		MaxItems: 2,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, planner, signer, broadcaster, confirmer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()

	w0 := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	w1 := withdraw.Withdrawal{ID: seq32(0x20), Amount: 2, FeeBps: 0, RecipientUA: []byte{0x02}, Expiry: now.Add(24 * time.Hour)}

	if err := c.IngestWithdrawRequested(ctx, w1); err != nil {
		t.Fatalf("IngestWithdrawRequested w1: %v", err)
	}
	if err := c.IngestWithdrawRequested(ctx, w0); err != nil {
		t.Fatalf("IngestWithdrawRequested w0: %v", err)
	}

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	if planner.calls != 1 || signer.calls != 1 || broadcaster.calls != 1 || confirmer.calls != 1 {
		t.Fatalf("unexpected call counts: planner=%d signer=%d broadcaster=%d confirmer=%d", planner.calls, signer.calls, broadcaster.calls, confirmer.calls)
	}

	confirmed, err := store.ListBatchesByState(ctx, withdraw.BatchStateConfirmed)
	if err != nil {
		t.Fatalf("ListBatchesByState: %v", err)
	}
	if len(confirmed) != 1 {
		t.Fatalf("expected 1 confirmed batch, got %d", len(confirmed))
	}
}

func TestCoordinator_ResumeFromPlannedBatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)

	ctx := context.Background()

	w0 := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w0)
	_, _ = store.ClaimUnbatched(ctx, "a", 10*time.Second, 10)

	batchID := seq32(0x99)
	if err := store.CreatePlannedBatch(ctx, "a", withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w0.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}

	planner := &stubPlanner{}
	signer := &stubSigner{}
	broadcaster := &stubBroadcaster{}
	confirmer := &stubConfirmer{}

	c, err := New(Config{
		Owner:    "a",
		MaxItems: 10,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, planner, signer, broadcaster, confirmer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if signer.calls != 1 || broadcaster.calls != 1 || confirmer.calls != 1 {
		t.Fatalf("unexpected resume calls: signer=%d broadcaster=%d confirmer=%d", signer.calls, broadcaster.calls, confirmer.calls)
	}
}

func TestCoordinator_BroadcastedPendingDoesNotFailTick(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, "a", 10*time.Second, 1)
	batchID := seq32(0x77)
	if err := store.CreatePlannedBatch(ctx, "a", withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}
	_ = store.MarkBatchSigning(ctx, batchID)
	_ = store.SetBatchSigned(ctx, batchID, []byte{0x01})
	_ = store.SetBatchBroadcasted(ctx, batchID, "tx1")

	confirmer := &stubConfirmer{errs: []error{ErrConfirmationPending, ErrConfirmationPending}}
	c, err := New(Config{
		Owner:    "a",
		MaxItems: 10,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, &stubPlanner{}, &stubSigner{}, &stubBroadcaster{}, confirmer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	b, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if b.State != withdraw.BatchStateBroadcasted {
		t.Fatalf("expected batch to remain broadcasted, got %s", b.State)
	}
}

func TestCoordinator_ReplansWhenBroadcastTxMissing(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, "a", 10*time.Second, 1)
	batchID := seq32(0x78)
	if err := store.CreatePlannedBatch(ctx, "a", withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}
	_ = store.MarkBatchSigning(ctx, batchID)
	_ = store.SetBatchSigned(ctx, batchID, []byte{0x01})
	_ = store.SetBatchBroadcasted(ctx, batchID, "tx-old")

	planner := &stubPlanner{}
	signer := &stubSigner{}
	broadcaster := &stubBroadcaster{}
	confirmer := &stubConfirmer{errs: []error{ErrConfirmationMissing, ErrConfirmationPending}}
	c, err := New(Config{
		Owner:    "a",
		MaxItems: 10,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, planner, signer, broadcaster, confirmer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	b, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if b.State != withdraw.BatchStateBroadcasted {
		t.Fatalf("expected batch to be re-broadcasted, got %s", b.State)
	}
	if b.JunoTxID != "tx1" {
		t.Fatalf("expected rebroadcast txid, got %q", b.JunoTxID)
	}
	if planner.calls != 1 {
		t.Fatalf("planner calls: got %d want 1", planner.calls)
	}
	if signer.calls != 1 {
		t.Fatalf("signer calls: got %d want 1", signer.calls)
	}
	if broadcaster.calls != 1 {
		t.Fatalf("broadcaster calls: got %d want 1", broadcaster.calls)
	}
}

func TestSigningSessionIDV1_DiffersAcrossPlans(t *testing.T) {
	t.Parallel()

	batchID := seq32(0x42)
	id0 := signingSessionIDV1(batchID, []byte(`{"v":1}`))
	id1 := signingSessionIDV1(batchID, []byte(`{"v":2}`))
	if id0 == id1 {
		t.Fatalf("expected different signing session ids for different plans")
	}
}

func TestCoordinator_RebroadcastBackoffSkipsUntilDue(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, "a", 10*time.Second, 1)
	batchID := seq32(0x79)
	if err := store.CreatePlannedBatch(ctx, "a", withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}
	_ = store.MarkBatchSigning(ctx, batchID)
	_ = store.SetBatchSigned(ctx, batchID, []byte{0x01})
	_ = store.SetBatchBroadcasted(ctx, batchID, "tx-old")

	planner := &stubPlanner{}
	signer := &stubSigner{}
	broadcaster := &stubBroadcaster{}
	confirmer := &stubConfirmer{
		errs: []error{
			ErrConfirmationMissing, // first tick triggers rebroadcast
			ErrConfirmationMissing, // second tick should skip due backoff
		},
	}
	c, err := New(Config{
		Owner:    "a",
		MaxItems: 10,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, planner, signer, broadcaster, confirmer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick #1: %v", err)
	}
	if planner.calls != 1 || signer.calls != 1 || broadcaster.calls != 1 {
		t.Fatalf("expected one recovery cycle after first tick")
	}

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick #2: %v", err)
	}
	if planner.calls != 1 || signer.calls != 1 || broadcaster.calls != 1 {
		t.Fatalf("expected no additional recovery during backoff window")
	}
}

func TestCoordinator_PersistsTxPlanAndSignedTxArtifacts(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	planner := &stubPlanner{}
	signer := &stubSigner{}
	broadcaster := &stubBroadcaster{}
	confirmer := &stubConfirmer{}
	artifacts := &recordingBlobStore{}

	c, err := New(Config{
		Owner:    "a",
		MaxItems: 1,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, planner, signer, broadcaster, confirmer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.WithBlobStore(artifacts)

	ctx := context.Background()
	w0 := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	if err := c.IngestWithdrawRequested(ctx, w0); err != nil {
		t.Fatalf("IngestWithdrawRequested: %v", err)
	}

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	batchID := batching.WithdrawalBatchIDV1([][32]byte{w0.ID})
	wantTxPlanKey := txPlanArtifactKey(batchID)
	wantSignedTxKey := signedTxArtifactKey(batchID)

	var sawTxPlan, sawSigned bool
	for _, p := range artifacts.puts {
		switch p.key {
		case wantTxPlanKey:
			sawTxPlan = true
			if got, want := string(p.payload), `{"v":1}`; got != want {
				t.Fatalf("txPlan payload mismatch: got %q want %q", got, want)
			}
			if got, want := p.opts.ContentType, "application/json"; got != want {
				t.Fatalf("txPlan content type mismatch: got %q want %q", got, want)
			}
		case wantSignedTxKey:
			sawSigned = true
			if len(p.payload) != 1 || p.payload[0] != 0x01 {
				t.Fatalf("signed tx payload mismatch: got %x", p.payload)
			}
			if got, want := p.opts.ContentType, "application/octet-stream"; got != want {
				t.Fatalf("signed tx content type mismatch: got %q want %q", got, want)
			}
		}
	}
	if !sawTxPlan {
		t.Fatalf("expected txPlan artifact key %q", wantTxPlanKey)
	}
	if !sawSigned {
		t.Fatalf("expected signed tx artifact key %q", wantSignedTxKey)
	}
}

func TestCoordinator_FailsWhenTxPlanArtifactPersistenceFails(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	planner := &stubPlanner{}
	signer := &stubSigner{}
	broadcaster := &stubBroadcaster{}
	confirmer := &stubConfirmer{}
	artifacts := &recordingBlobStore{putErr: errors.New("s3 unavailable")}

	c, err := New(Config{
		Owner:    "a",
		MaxItems: 1,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, planner, signer, broadcaster, confirmer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.WithBlobStore(artifacts)

	ctx := context.Background()
	w0 := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	if err := c.IngestWithdrawRequested(ctx, w0); err != nil {
		t.Fatalf("IngestWithdrawRequested: %v", err)
	}

	err = c.Tick(ctx)
	if err == nil {
		t.Fatalf("expected Tick error")
	}
	if !strings.Contains(err.Error(), "persist tx plan artifact") {
		t.Fatalf("expected artifact error, got %v", err)
	}
	if signer.calls != 0 || broadcaster.calls != 0 {
		t.Fatalf("expected no sign/broadcast on artifact failure, got signer=%d broadcaster=%d", signer.calls, broadcaster.calls)
	}
}
