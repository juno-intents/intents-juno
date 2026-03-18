package withdrawcoordinator

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/juno-intents/intents-juno/internal/batching"
	"github.com/juno-intents/intents-juno/internal/blobstore"
	"github.com/juno-intents/intents-juno/internal/dlq"
	"github.com/juno-intents/intents-juno/internal/leases"
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

type leaseStealingPlanner struct {
	leaseStore leases.Store
	now        *time.Time
	ttl        time.Duration
	calls      int
}

func (p *leaseStealingPlanner) Plan(ctx context.Context, _ [32]byte, _ []withdraw.Withdrawal) ([]byte, error) {
	p.calls++
	*p.now = (*p.now).Add(p.ttl + time.Second)
	if _, ok, err := p.leaseStore.TryAcquire(ctx, "withdraw-coordinator", "b", p.ttl); err != nil {
		return nil, err
	} else if !ok {
		return nil, errors.New("failed to steal leader lease")
	}
	return []byte(`{"v":1}`), nil
}

type sequencePlanner struct {
	calls int
	plans [][]byte
}

func (p *sequencePlanner) Plan(_ context.Context, _ [32]byte, _ []withdraw.Withdrawal) ([]byte, error) {
	if len(p.plans) == 0 {
		return nil, errors.New("no plans configured")
	}
	p.calls++
	idx := p.calls - 1
	if idx >= len(p.plans) {
		idx = len(p.plans) - 1
	}
	return append([]byte(nil), p.plans[idx]...), nil
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

type txPlanAwareSigner struct {
	calls int
	plans []string
}

func (s *txPlanAwareSigner) Sign(_ context.Context, _ [32]byte, txPlan []byte) ([]byte, error) {
	s.calls++
	s.plans = append(s.plans, string(txPlan))
	switch string(txPlan) {
	case `{"v":1}`:
		return nil, errors.New(`sign txplan: tsssigner: ext-prepare failed: exit status 1: {"error":{"code":"prepare_failed","message":"txsign: note_decrypt_failed"},"status":"err","version":"v1"}`)
	case `{"v":2}`:
		return []byte{0x02}, nil
	default:
		return nil, errors.New("unexpected tx plan")
	}
}

type resigningSigner struct {
	calls int
	plans []string
}

func (s *resigningSigner) Sign(_ context.Context, _ [32]byte, txPlan []byte) ([]byte, error) {
	s.calls++
	s.plans = append(s.plans, string(txPlan))
	switch string(txPlan) {
	case `{"v":2}`:
		return []byte{0x02}, nil
	default:
		return nil, errors.New("unexpected tx plan")
	}
}

type stubBroadcaster struct {
	calls int
	txid  string
}

func (b *stubBroadcaster) Broadcast(_ context.Context, rawTx []byte) (string, error) {
	_ = rawTx
	b.calls++
	if b.txid != "" {
		return b.txid, nil
	}
	return "tx1", nil
}

type staleThenSuccessBroadcaster struct {
	calls   int
	payload [][]byte
}

func (b *staleThenSuccessBroadcaster) Broadcast(_ context.Context, rawTx []byte) (string, error) {
	b.calls++
	b.payload = append(b.payload, append([]byte(nil), rawTx...))
	switch {
	case len(rawTx) == 1 && rawTx[0] == 0x01:
		return "", errors.New("junorpc: rpc error code -26: tx-expiring-soon: expiryheight is 127844 but should be at least 127876 to avoid transaction expiring soon")
	case len(rawTx) == 1 && rawTx[0] == 0x02:
		return "tx-new", nil
	default:
		return "", errors.New("unexpected raw tx")
	}
}

type txAwareBroadcaster struct {
	calls int
}

func (b *txAwareBroadcaster) Broadcast(_ context.Context, rawTx []byte) (string, error) {
	b.calls++
	switch {
	case bytes.Equal(rawTx, []byte{0x01}):
		return "", errors.New("junorpc: rpc error code -26: tx-expiring-soon: expiryheight is 127844 but should be at least 127876 to avoid transaction expiring soon")
	case bytes.Equal(rawTx, []byte{0x02}):
		return "tx-replanned", nil
	default:
		return "", errors.New("unexpected signed tx payload")
	}
}

type sequenceSigner struct {
	calls int
	plans []string
}

func (s *sequenceSigner) Sign(_ context.Context, _ [32]byte, txPlan []byte) ([]byte, error) {
	s.calls++
	s.plans = append(s.plans, string(txPlan))
	switch string(txPlan) {
	case `{"v":1}`:
		return []byte{0x01}, nil
	case `{"v":2}`:
		return []byte{0x02}, nil
	default:
		return nil, errors.New("unexpected tx plan")
	}
}

type txPlanAwareBroadcaster struct {
	calls int
	rawTx [][]byte
}

func (b *txPlanAwareBroadcaster) Broadcast(_ context.Context, rawTx []byte) (string, error) {
	b.calls++
	b.rawTx = append(b.rawTx, append([]byte(nil), rawTx...))
	switch {
	case len(rawTx) == 1 && rawTx[0] == 0x01:
		return "", errors.New("junorpc: rpc error code -26: tx-expiring-soon: expiryheight is 127844 but should be at least 127876 to avoid transaction expiring soon")
	case len(rawTx) == 1 && rawTx[0] == 0x02:
		return "tx-fresh", nil
	default:
		return "", errors.New("unexpected raw tx")
	}
}

type flakyDLQStore struct {
	inner         dlq.Store
	depositErrs   []error
	withdrawErrs  []error
	depositCalls  int
	withdrawCalls int
}

func newFlakyDLQStore() *flakyDLQStore {
	return &flakyDLQStore{inner: dlq.NewMemoryStore(nil)}
}

func (s *flakyDLQStore) EnsureSchema(ctx context.Context) error {
	return s.inner.EnsureSchema(ctx)
}

func (s *flakyDLQStore) InsertProofDLQ(ctx context.Context, rec dlq.ProofDLQRecord) error {
	return s.inner.InsertProofDLQ(ctx, rec)
}

func (s *flakyDLQStore) InsertDepositBatchDLQ(ctx context.Context, rec dlq.DepositBatchDLQRecord) error {
	s.depositCalls++
	if idx := s.depositCalls - 1; idx < len(s.depositErrs) && s.depositErrs[idx] != nil {
		return s.depositErrs[idx]
	}
	return s.inner.InsertDepositBatchDLQ(ctx, rec)
}

func (s *flakyDLQStore) InsertWithdrawalBatchDLQ(ctx context.Context, rec dlq.WithdrawalBatchDLQRecord) error {
	s.withdrawCalls++
	if idx := s.withdrawCalls - 1; idx < len(s.withdrawErrs) && s.withdrawErrs[idx] != nil {
		return s.withdrawErrs[idx]
	}
	return s.inner.InsertWithdrawalBatchDLQ(ctx, rec)
}

func (s *flakyDLQStore) ListProofDLQ(ctx context.Context, filter dlq.DLQFilter) ([]dlq.ProofDLQRecord, error) {
	return s.inner.ListProofDLQ(ctx, filter)
}

func (s *flakyDLQStore) ListDepositBatchDLQ(ctx context.Context, filter dlq.DLQFilter) ([]dlq.DepositBatchDLQRecord, error) {
	return s.inner.ListDepositBatchDLQ(ctx, filter)
}

func (s *flakyDLQStore) ListWithdrawalBatchDLQ(ctx context.Context, filter dlq.DLQFilter) ([]dlq.WithdrawalBatchDLQRecord, error) {
	return s.inner.ListWithdrawalBatchDLQ(ctx, filter)
}

func (s *flakyDLQStore) CountUnacknowledged(ctx context.Context) (dlq.DLQCounts, error) {
	return s.inner.CountUnacknowledged(ctx)
}

func (s *flakyDLQStore) Acknowledge(ctx context.Context, table string, id []byte) error {
	return s.inner.Acknowledge(ctx, table, id)
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

func testWithdrawFence(owner string) withdraw.Fence {
	return withdraw.Fence{Owner: owner, LeaseVersion: 1}
}

func newCoordinatorForTest(cfg Config, store withdraw.Store, planner Planner, signer Signer, broadcaster Broadcaster, confirmer Confirmer, log *slog.Logger) (*Coordinator, error) {
	c, err := New(cfg, store, planner, signer, broadcaster, confirmer, &stubTxChecker{}, log)
	if err != nil {
		return nil, err
	}
	c.WithPaidMarker(&stubPaidMarker{})
	return c, nil
}

func TestCoordinator_BuildsSignsBroadcastsAndConfirms_OnMaxItems(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	planner := &stubPlanner{}
	signer := &stubSigner{}
	broadcaster := &stubBroadcaster{txid: "tx-old"}
	confirmer := &stubConfirmer{}

	c, err := newCoordinatorForTest(Config{
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
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 10)

	batchID := seq32(0x99)
	if err := store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w0.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}

	planner := &stubPlanner{}
	signer := &stubSigner{}
	broadcaster := &stubBroadcaster{txid: "tx-old"}
	confirmer := &stubConfirmer{}

	c, err := newCoordinatorForTest(Config{
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

func TestCoordinator_TickRejectsStaleLeaderLeaseAfterPlannerPause(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	leaseStore := leases.NewMemoryStore(nowFn)
	ctx := context.Background()
	lease, ok, err := leaseStore.TryAcquire(ctx, "withdraw-coordinator", "a", 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("TryAcquire leader lease: ok=%v err=%v", ok, err)
	}

	store := withdraw.NewMemoryStore(nowFn)
	planner := &leaseStealingPlanner{
		leaseStore: leaseStore,
		now:        &now,
		ttl:        10 * time.Second,
	}

	c, err := newCoordinatorForTest(Config{
		Owner:            "a",
		MaxItems:         1,
		MaxAge:           3 * time.Minute,
		ClaimTTL:         10 * time.Second,
		LeaderLeaseStore: leaseStore,
		Now:              nowFn,
	}, store, planner, &stubSigner{}, &stubBroadcaster{txid: "tx1"}, &stubConfirmer{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.SetLeaderLease(lease)

	w := withdraw.Withdrawal{ID: seq32(0x31), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	if err := c.IngestWithdrawRequested(ctx, w); err != nil {
		t.Fatalf("IngestWithdrawRequested: %v", err)
	}

	err = c.Tick(ctx)
	if !errors.Is(err, ErrLeadershipLost) {
		t.Fatalf("expected ErrLeadershipLost, got %v", err)
	}

	planned, err := store.ListBatchesByState(ctx, withdraw.BatchStatePlanned)
	if err != nil {
		t.Fatalf("ListBatchesByState: %v", err)
	}
	if len(planned) != 0 {
		t.Fatalf("expected no planned batches after leadership loss, got %d", len(planned))
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
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x77)
	if err := store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}
	_ = store.MarkBatchSigning(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchSigned(ctx, batchID, testWithdrawFence("a"), []byte{0x01})
	_ = store.MarkBatchBroadcastLocked(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchBroadcasted(ctx, batchID, testWithdrawFence("a"), "tx1")

	confirmer := &stubConfirmer{errs: []error{ErrConfirmationPending, ErrConfirmationPending}}
	c, err := newCoordinatorForTest(Config{
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
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x78)
	if err := store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}
	_ = store.MarkBatchSigning(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchSigned(ctx, batchID, testWithdrawFence("a"), []byte{0x01})
	_ = store.MarkBatchBroadcastLocked(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchBroadcasted(ctx, batchID, testWithdrawFence("a"), "tx-old")

	planner := &stubPlanner{}
	signer := &stubSigner{}
	broadcaster := &stubBroadcaster{txid: "tx-old"}
	confirmer := &stubConfirmer{errs: []error{ErrConfirmationMissing, ErrConfirmationPending}}
	c, err := newCoordinatorForTest(Config{
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
	if b.JunoTxID != "tx-old" {
		t.Fatalf("expected rebroadcast to keep original txid, got %q", b.JunoTxID)
	}
	if planner.calls != 0 {
		t.Fatalf("planner calls: got %d want 0", planner.calls)
	}
	if signer.calls != 0 {
		t.Fatalf("signer calls: got %d want 0", signer.calls)
	}
	if broadcaster.calls != 1 {
		t.Fatalf("broadcaster calls: got %d want 1", broadcaster.calls)
	}
}

func TestCoordinator_ReplansWhenSigningPlanTurnsStale(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x11), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x7a)
	if err := store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}

	planner := &sequencePlanner{plans: [][]byte{[]byte(`{"v":2}`)}}
	signer := &txPlanAwareSigner{}
	broadcaster := &stubBroadcaster{txid: "tx-old"}
	confirmer := &stubConfirmer{errs: []error{ErrConfirmationPending}}
	dlqStore := dlq.NewMemoryStore(nil)

	c, err := newCoordinatorForTest(Config{
		Owner:    "a",
		MaxItems: 10,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		DLQStore: dlqStore,
		Now:      nowFn,
	}, store, planner, signer, broadcaster, confirmer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	if planner.calls != 1 {
		t.Fatalf("planner calls: got %d want 1", planner.calls)
	}
	if signer.calls != 2 {
		t.Fatalf("signer calls: got %d want 2", signer.calls)
	}
	if got, want := signer.plans, []string{`{"v":1}`, `{"v":2}`}; !bytes.Equal([]byte(strings.Join(got, ",")), []byte(strings.Join(want, ","))) {
		t.Fatalf("signer plans: got %v want %v", got, want)
	}
	if broadcaster.calls != 1 {
		t.Fatalf("broadcaster calls: got %d want 1", broadcaster.calls)
	}

	b, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if b.State != withdraw.BatchStateConfirmed {
		t.Fatalf("expected batch to recover to confirmed, got %s", b.State)
	}
	if got, want := string(b.TxPlan), `{"v":2}`; got != want {
		t.Fatalf("tx plan after recovery: got %q want %q", got, want)
	}

	counts, err := dlqStore.CountUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("CountUnacknowledged: %v", err)
	}
	if counts.WithdrawalBatches != 0 {
		t.Fatalf("expected no withdrawal DLQ entries, got %d", counts.WithdrawalBatches)
	}
}

func TestCoordinator_BroadcastLockedBatchDoesNotReplanWhenSignedTxTurnsStale(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x12), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x7b)
	if err := store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}
	if err := store.MarkBatchSigning(ctx, batchID, testWithdrawFence("a")); err != nil {
		t.Fatalf("MarkBatchSigning: %v", err)
	}
	if err := store.SetBatchSigned(ctx, batchID, testWithdrawFence("a"), []byte{0x01}); err != nil {
		t.Fatalf("SetBatchSigned: %v", err)
	}

	broadcaster := &txPlanAwareBroadcaster{}
	confirmer := &stubConfirmer{errs: []error{ErrConfirmationPending}}

	c, err := newCoordinatorForTest(Config{
		Owner:    "a",
		MaxItems: 10,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, &sequencePlanner{plans: [][]byte{[]byte(`{"v":2}`)}}, &txPlanAwareSigner{}, broadcaster, confirmer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = c.broadcastBatch(ctx, batchID)
	if err == nil {
		t.Fatal("expected stale signed-tx broadcast error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "tx-expiring-soon") {
		t.Fatalf("expected tx-expiring-soon error, got %v", err)
	}

	b, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if b.State != withdraw.BatchStateSigned {
		t.Fatalf("expected batch to remain signed, got %s", b.State)
	}
	if b.JunoTxID != "" {
		t.Fatalf("juno txid: got %q want empty", b.JunoTxID)
	}
	if got, want := string(b.TxPlan), `{"v":1}`; got != want {
		t.Fatalf("tx plan after broadcast failure: got %q want %q", got, want)
	}
	if broadcaster.calls != 1 {
		t.Fatalf("broadcaster calls: got %d want 1", broadcaster.calls)
	}
	if len(broadcaster.rawTx) != 1 || broadcaster.rawTx[0][0] != 0x01 {
		t.Fatalf("unexpected raw tx sequence: %v", broadcaster.rawTx)
	}
	if b.BroadcastLockedAt.IsZero() {
		t.Fatal("expected broadcast lock to be persisted")
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
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x79)
	if err := store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}
	_ = store.MarkBatchSigning(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchSigned(ctx, batchID, testWithdrawFence("a"), []byte{0x01})
	_ = store.MarkBatchBroadcastLocked(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchBroadcasted(ctx, batchID, testWithdrawFence("a"), "tx-old")

	planner := &stubPlanner{}
	signer := &stubSigner{}
	broadcaster := &stubBroadcaster{txid: "tx-old"}
	confirmer := &stubConfirmer{
		errs: []error{
			ErrConfirmationMissing, // first tick triggers rebroadcast
			ErrConfirmationMissing, // second tick should skip due backoff
		},
	}
	c, err := newCoordinatorForTest(Config{
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
	if planner.calls != 0 || signer.calls != 0 || broadcaster.calls != 1 {
		t.Fatalf("expected one rebroadcast without replanning after first tick")
	}

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick #2: %v", err)
	}
	if planner.calls != 0 || signer.calls != 0 || broadcaster.calls != 1 {
		t.Fatalf("expected no additional recovery during backoff window")
	}
}

func TestCoordinator_DoesNotReplanSignedBatchAfterTxExpiringSoonBroadcastError(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{
		ID:          seq32(0x91),
		Amount:      1,
		FeeBps:      0,
		RecipientUA: []byte{0x01},
		Expiry:      now.Add(24 * time.Hour),
	}
	if _, _, err := store.UpsertRequested(ctx, w); err != nil {
		t.Fatalf("UpsertRequested: %v", err)
	}

	planner := &sequencePlanner{plans: [][]byte{[]byte(`{"v":1}`)}}
	signer := &sequenceSigner{}
	broadcaster := &txAwareBroadcaster{}
	confirmer := &stubConfirmer{}

	c, err := New(Config{
		Owner:    "a",
		MaxItems: 1,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, planner, signer, broadcaster, confirmer, &stubTxChecker{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = c.Tick(ctx)
	if err == nil {
		t.Fatal("expected broadcast error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "tx-expiring-soon") {
		t.Fatalf("expected tx-expiring-soon error, got %v", err)
	}
	if planner.calls != 1 {
		t.Fatalf("planner calls: got %d want 1", planner.calls)
	}
	if signer.calls != 1 {
		t.Fatalf("signer calls: got %d want 1", signer.calls)
	}
	if got, want := signer.plans, []string{`{"v":1}`}; !bytes.Equal([]byte(strings.Join(got, ",")), []byte(strings.Join(want, ","))) {
		t.Fatalf("signer plans: got %v want %v", got, want)
	}
	if broadcaster.calls != 1 {
		t.Fatalf("broadcaster calls: got %d want 1", broadcaster.calls)
	}

	b, err := store.GetBatch(ctx, batching.WithdrawalBatchIDV1([][32]byte{w.ID}))
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if b.State != withdraw.BatchStateSigned {
		t.Fatalf("batch state: got %s want %s", b.State, withdraw.BatchStateSigned)
	}
	if got, want := string(b.TxPlan), `{"v":1}`; got != want {
		t.Fatalf("tx plan after failure: got %q want %q", got, want)
	}
	if b.JunoTxID != "" {
		t.Fatalf("juno txid: got %q want empty", b.JunoTxID)
	}
	if b.BroadcastLockedAt.IsZero() {
		t.Fatal("expected broadcast lock to be persisted")
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

	c, err := newCoordinatorForTest(Config{
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

func TestCoordinator_DedupesReclaimedWithdrawalBeforeFlush(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	planner := &stubPlanner{}
	signer := &stubSigner{}
	broadcaster := &stubBroadcaster{}
	confirmer := &stubConfirmer{}

	c, err := newCoordinatorForTest(Config{
		Owner:    "a",
		MaxItems: 10,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 30 * time.Second,
		Now:      nowFn,
	}, store, planner, signer, broadcaster, confirmer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	w := withdraw.Withdrawal{
		ID:          seq32(0x00),
		Amount:      1,
		FeeBps:      0,
		RecipientUA: []byte{0x01},
		Expiry:      now.Add(24 * time.Hour),
	}
	if err := c.IngestWithdrawRequested(ctx, w); err != nil {
		t.Fatalf("IngestWithdrawRequested: %v", err)
	}

	// Claim once, then repeatedly advance beyond claim TTL but below/at max age.
	// Coordinator must not duplicate the same withdrawal in the in-memory batch.
	for i := 0; i < 6; i++ {
		if err := c.Tick(ctx); err != nil {
			t.Fatalf("Tick #%d: %v", i+1, err)
		}
		now = now.Add(40 * time.Second)
	}

	confirmed, err := store.ListBatchesByState(ctx, withdraw.BatchStateConfirmed)
	if err != nil {
		t.Fatalf("ListBatchesByState: %v", err)
	}
	if len(confirmed) != 1 {
		t.Fatalf("expected 1 confirmed batch, got %d", len(confirmed))
	}
	if len(confirmed[0].WithdrawalIDs) != 1 {
		t.Fatalf("expected 1 withdrawal id in batch, got %d", len(confirmed[0].WithdrawalIDs))
	}
	if confirmed[0].WithdrawalIDs[0] != w.ID {
		t.Fatalf("batch withdrawal id mismatch")
	}
	if planner.calls != 1 || signer.calls != 1 || broadcaster.calls != 1 || confirmer.calls != 1 {
		t.Fatalf("unexpected call counts: planner=%d signer=%d broadcaster=%d confirmer=%d", planner.calls, signer.calls, broadcaster.calls, confirmer.calls)
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

	c, err := newCoordinatorForTest(Config{
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

type stubTxChecker struct {
	statuses  []string
	errs      []error
	calls     int
	tipHeight uint64
}

type stubPaidMarker struct {
	calls int
	got   [][][32]byte
	err   error
}

func (m *stubPaidMarker) MarkPaid(_ context.Context, withdrawalIDs [][32]byte) error {
	m.calls++
	cp := make([][32]byte, len(withdrawalIDs))
	copy(cp, withdrawalIDs)
	m.got = append(m.got, cp)
	return m.err
}

type failingExpiryExtender struct {
	calls int
	err   error
}

func (e *failingExpiryExtender) Extend(_ context.Context, _ [][32]byte, _ time.Time) error {
	e.calls++
	return e.err
}

func (c *stubTxChecker) TxStatus(_ context.Context, txid string) (string, error) {
	_ = txid
	c.calls++
	idx := c.calls - 1
	if idx < len(c.errs) && c.errs[idx] != nil {
		return "", c.errs[idx]
	}
	if idx < len(c.statuses) {
		return c.statuses[idx], nil
	}
	return TxStatusMissing, nil
}

func (c *stubTxChecker) TipHeight(_ context.Context) (uint64, error) {
	c.tipHeight++
	return c.tipHeight, nil
}

func TestCoordinator_NewRequiresTxChecker(t *testing.T) {
	t.Parallel()

	_, err := New(Config{
		Owner:    "a",
		MaxItems: 1,
		MaxAge:   time.Minute,
		ClaimTTL: time.Second,
		Now:      time.Now,
	}, withdraw.NewMemoryStore(time.Now), &stubPlanner{}, &stubSigner{}, &stubBroadcaster{}, &stubConfirmer{}, nil, nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestCoordinator_DoubleSpendPrevention_TxConfirmed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x80)
	_ = store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})
	_ = store.MarkBatchSigning(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchSigned(ctx, batchID, testWithdrawFence("a"), []byte{0x01})
	_ = store.MarkBatchBroadcastLocked(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchBroadcasted(ctx, batchID, testWithdrawFence("a"), "tx-existing")

	planner := &stubPlanner{}
	signer := &stubSigner{}
	broadcaster := &stubBroadcaster{}
	confirmer := &stubConfirmer{errs: []error{ErrConfirmationMissing}}
	txChecker := &stubTxChecker{statuses: []string{TxStatusConfirmed}}
	paidMarker := &stubPaidMarker{}

	c, err := New(Config{
		Owner:    "a",
		MaxItems: 10,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, planner, signer, broadcaster, confirmer, txChecker, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.WithPaidMarker(paidMarker)

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	// Tx was confirmed on-chain, so no rebroadcast should occur.
	if planner.calls != 0 || broadcaster.calls != 0 {
		t.Fatalf("expected no rebroadcast when tx is confirmed: planner=%d broadcaster=%d", planner.calls, broadcaster.calls)
	}

	b, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if b.State != withdraw.BatchStateConfirmed {
		t.Fatalf("expected batch confirmed, got %s", b.State)
	}
	if paidMarker.calls != 1 {
		t.Fatalf("paid marker calls: got %d want 1", paidMarker.calls)
	}
	status, err := store.GetWithdrawalStatus(ctx, w.ID)
	if err != nil {
		t.Fatalf("GetWithdrawalStatus: %v", err)
	}
	if status != withdraw.WithdrawalStatusPaid {
		t.Fatalf("status: got %s want %s", status, withdraw.WithdrawalStatusPaid)
	}
}

func TestCoordinator_DoubleSpendPrevention_TxInMempool(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x81)
	_ = store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})
	_ = store.MarkBatchSigning(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchSigned(ctx, batchID, testWithdrawFence("a"), []byte{0x01})
	_ = store.MarkBatchBroadcastLocked(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchBroadcasted(ctx, batchID, testWithdrawFence("a"), "tx-in-mempool")

	// Tick calls resume() twice (beginning + end), so the confirmer is called twice.
	// Both calls should return ErrConfirmationMissing so the batch stays broadcasted.
	confirmer := &stubConfirmer{errs: []error{ErrConfirmationMissing, ErrConfirmationMissing}}
	txChecker := &stubTxChecker{statuses: []string{TxStatusMempool, TxStatusMempool}}
	broadcaster := &stubBroadcaster{}

	c, err := New(Config{
		Owner:    "a",
		MaxItems: 10,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, &stubPlanner{}, &stubSigner{}, broadcaster, confirmer, txChecker, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	// Tx is in mempool, so no rebroadcast should occur.
	if broadcaster.calls != 0 {
		t.Fatalf("expected no rebroadcast when tx is in mempool: broadcaster=%d", broadcaster.calls)
	}

	b, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if b.State != withdraw.BatchStateBroadcasted {
		t.Fatalf("expected batch to remain broadcasted, got %s", b.State)
	}
}

func TestCoordinator_MaxRebroadcastAttempts(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x82)
	_ = store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})
	_ = store.MarkBatchSigning(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchSigned(ctx, batchID, testWithdrawFence("a"), []byte{0x01})
	_ = store.MarkBatchBroadcastLocked(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchBroadcasted(ctx, batchID, testWithdrawFence("a"), "tx-gone")
	// Set RebroadcastAttempts to the max.
	_ = store.SetBatchRebroadcastBackoff(ctx, batchID, testWithdrawFence("a"), 5, now.Add(-1*time.Hour))

	confirmer := &stubConfirmer{errs: []error{ErrConfirmationMissing}}

	c, err := newCoordinatorForTest(Config{
		Owner:                  "a",
		MaxItems:               10,
		MaxAge:                 3 * time.Minute,
		ClaimTTL:               10 * time.Second,
		MaxRebroadcastAttempts: 5,
		Now:                    nowFn,
	}, store, &stubPlanner{}, &stubSigner{}, &stubBroadcaster{}, confirmer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = c.Tick(ctx)
	if err == nil {
		t.Fatal("expected ErrRebroadcastExhausted")
	}
	if !errors.Is(err, ErrRebroadcastExhausted) {
		t.Fatalf("expected ErrRebroadcastExhausted, got %v", err)
	}
}

func TestCoordinator_WaitOneBlock_TxAppearsInMempool(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x10), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x83)
	_ = store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})
	_ = store.MarkBatchSigning(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchSigned(ctx, batchID, testWithdrawFence("a"), []byte{0x01})
	_ = store.MarkBatchBroadcastLocked(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchBroadcasted(ctx, batchID, testWithdrawFence("a"), "tx-slow-propagate")

	// Tick calls resume() twice (beginning + end).
	// Pass 1: TxStatusMissing triggers an immediate same-bytes rebroadcast.
	// Pass 2: TxStatusMempool leaves the batch in broadcasted state.
	txChecker := &stubTxChecker{statuses: []string{
		TxStatusMissing, TxStatusMempool, // pass 1
		TxStatusMissing, TxStatusMempool, // pass 2
	}}
	confirmer := &stubConfirmer{errs: []error{ErrConfirmationMissing, ErrConfirmationMissing}}
	broadcaster := &stubBroadcaster{txid: "tx-slow-propagate"}
	paidMarker := &stubPaidMarker{}

	c, err := New(Config{
		Owner:    "a",
		MaxItems: 10,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, &stubPlanner{}, &stubSigner{}, broadcaster, confirmer, txChecker, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.WithPaidMarker(paidMarker)

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	// A missing tx now schedules an immediate same-bytes rebroadcast and leaves the batch broadcasted.
	if broadcaster.calls != 1 {
		t.Fatalf("expected exactly one rebroadcast after tx went missing, got broadcaster=%d", broadcaster.calls)
	}

	b, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if b.State != withdraw.BatchStateBroadcasted {
		t.Fatalf("expected batch to remain broadcasted, got %s", b.State)
	}
	if paidMarker.calls != 0 {
		t.Fatalf("expected no paid marker calls while tx stays in mempool, got %d", paidMarker.calls)
	}
}

func TestCoordinator_WaitOneBlock_TxConfirmedAfterBlock(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x11), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x84)
	_ = store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})
	_ = store.MarkBatchSigning(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchSigned(ctx, batchID, testWithdrawFence("a"), []byte{0x01})
	_ = store.MarkBatchBroadcastLocked(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchBroadcasted(ctx, batchID, testWithdrawFence("a"), "tx-confirmed-late")

	// First pass sees the tx as missing and rebroadcasts the same signed bytes.
	// Second pass confirms the tx and finalizes the batch.
	txChecker := &stubTxChecker{statuses: []string{TxStatusMissing}}
	confirmer := &stubConfirmer{errs: []error{ErrConfirmationMissing}}
	broadcaster := &stubBroadcaster{txid: "tx-confirmed-late"}
	paidMarker := &stubPaidMarker{}

	c, err := New(Config{
		Owner:    "a",
		MaxItems: 10,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, &stubPlanner{}, &stubSigner{}, broadcaster, confirmer, txChecker, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.WithPaidMarker(paidMarker)

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	if broadcaster.calls != 1 {
		t.Fatalf("expected one rebroadcast before confirmation, got broadcaster=%d", broadcaster.calls)
	}

	b, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if b.State != withdraw.BatchStateConfirmed {
		t.Fatalf("expected batch confirmed, got %s", b.State)
	}
	if paidMarker.calls != 1 {
		t.Fatalf("paid marker calls: got %d want 1", paidMarker.calls)
	}
}

func TestCoordinator_ConfirmedTxWithoutSuccessfulPaidMarkerPersistsJunoConfirmedRetryState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()
	dlqStore := dlq.NewMemoryStore(nil)

	w := withdraw.Withdrawal{ID: seq32(0x12), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x85)
	_ = store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})
	_ = store.MarkBatchSigning(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchSigned(ctx, batchID, testWithdrawFence("a"), []byte{0x01})
	_ = store.MarkBatchBroadcastLocked(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchBroadcasted(ctx, batchID, testWithdrawFence("a"), "tx-paid-marker-fail")

	txChecker := &stubTxChecker{statuses: []string{TxStatusConfirmed}}
	confirmer := &stubConfirmer{errs: []error{ErrConfirmationMissing}}
	paidMarker := &stubPaidMarker{err: errors.New("base relay unavailable")}

	c, err := New(Config{
		Owner:    "a",
		MaxItems: 10,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		DLQStore: dlqStore,
		Now:      nowFn,
	}, store, &stubPlanner{}, &stubSigner{}, &stubBroadcaster{}, confirmer, txChecker, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.WithPaidMarker(paidMarker)

	if err := c.Tick(ctx); err == nil {
		t.Fatal("expected error")
	}

	b, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if b.State != withdraw.BatchStateJunoConfirmed {
		t.Fatalf("expected batch to remain juno-confirmed, got %s", b.State)
	}
	status, err := store.GetWithdrawalStatus(ctx, w.ID)
	if err != nil {
		t.Fatalf("GetWithdrawalStatus: %v", err)
	}
	if status != withdraw.WithdrawalStatusBatched {
		t.Fatalf("status: got %s want %s", status, withdraw.WithdrawalStatusBatched)
	}
	if b.MarkPaidFailures != 1 {
		t.Fatalf("mark_paid_failures: got %d want 1", b.MarkPaidFailures)
	}
	if !c.MarkPaidCircuitOpen() {
		t.Fatal("expected mark-paid circuit to open while juno-confirmed batch is unrecorded")
	}

	for i := 0; i < 3; i++ {
		now = now.Add(15 * time.Minute)
		if err := c.Tick(ctx); err == nil {
			t.Fatal("expected repeated mark-paid retry error")
		}
	}

	counts, err := dlqStore.CountUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("CountUnacknowledged: %v", err)
	}
	if counts.WithdrawalBatches != 0 {
		t.Fatalf("expected no withdrawal DLQ entries for juno-confirmed retry path, got %d", counts.WithdrawalBatches)
	}
}

func TestCoordinator_JunoConfirmedBatchBlocksNewClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	stuck := withdraw.Withdrawal{ID: seq32(0x20), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(30 * time.Second)}
	_, _, _ = store.UpsertRequested(ctx, stuck)
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	stuckBatchID := seq32(0x86)
	_ = store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            stuckBatchID,
		WithdrawalIDs: [][32]byte{stuck.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})
	_ = store.MarkBatchSigning(ctx, stuckBatchID, testWithdrawFence("a"))
	_ = store.SetBatchSigned(ctx, stuckBatchID, testWithdrawFence("a"), []byte{0x01})
	_ = store.MarkBatchBroadcastLocked(ctx, stuckBatchID, testWithdrawFence("a"))
	_ = store.SetBatchBroadcasted(ctx, stuckBatchID, testWithdrawFence("a"), "tx-stuck")
	_ = store.MarkBatchJunoConfirmed(ctx, stuckBatchID, testWithdrawFence("a"))

	fresh := withdraw.Withdrawal{ID: seq32(0x21), Amount: 2, FeeBps: 0, RecipientUA: []byte{0x02}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, fresh)

	planner := &stubPlanner{}
	signer := &stubSigner{}
	broadcaster := &stubBroadcaster{txid: "tx-fresh"}
	confirmer := &stubConfirmer{errs: []error{
		nil,
		ErrConfirmationPending,
		ErrConfirmationPending,
	}}
	paidMarker := &stubPaidMarker{err: errors.New("base relay unavailable")}

	c, err := New(Config{
		Owner:    "a",
		MaxItems: 1,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, planner, signer, broadcaster, confirmer, &stubTxChecker{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.WithPaidMarker(paidMarker)

	err = c.Tick(ctx)
	if err == nil {
		t.Fatal("expected Tick error")
	}
	if !strings.Contains(err.Error(), "base relay unavailable") {
		t.Fatalf("expected paid marker error, got %v", err)
	}
	if paidMarker.calls != 1 {
		t.Fatalf("paid marker calls: got %d want 1", paidMarker.calls)
	}
	if planner.calls != 0 {
		t.Fatalf("planner calls: got %d want 0", planner.calls)
	}
	if signer.calls != 0 {
		t.Fatalf("signer calls: got %d want 0", signer.calls)
	}
	if broadcaster.calls != 0 {
		t.Fatalf("broadcaster calls: got %d want 0", broadcaster.calls)
	}

	status, err := store.GetWithdrawalStatus(ctx, fresh.ID)
	if err != nil {
		t.Fatalf("GetWithdrawalStatus: %v", err)
	}
	if status != withdraw.WithdrawalStatusRequested {
		t.Fatalf("fresh status: got %s want %s", status, withdraw.WithdrawalStatusRequested)
	}

	if _, err := store.GetBatch(ctx, batching.WithdrawalBatchIDV1([][32]byte{fresh.ID})); !errors.Is(err, withdraw.ErrNotFound) {
		t.Fatalf("expected no batch for fresh withdrawal while mark-paid circuit is open, got %v", err)
	}
	if !c.MarkPaidCircuitOpen() {
		t.Fatal("expected mark-paid circuit to remain open")
	}
}

func TestCoordinator_DLQ_RebroadcastExhausted(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x90)
	_ = store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})
	_ = store.MarkBatchSigning(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchSigned(ctx, batchID, testWithdrawFence("a"), []byte{0x01})
	_ = store.MarkBatchBroadcastLocked(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchBroadcasted(ctx, batchID, testWithdrawFence("a"), "tx-gone")
	// Set RebroadcastAttempts to the max.
	_ = store.SetBatchRebroadcastBackoff(ctx, batchID, testWithdrawFence("a"), 2, now.Add(-1*time.Hour))

	confirmer := &stubConfirmer{errs: []error{ErrConfirmationMissing}}
	dlqStore := dlq.NewMemoryStore(nil)

	c, err := newCoordinatorForTest(Config{
		Owner:                  "a",
		MaxItems:               10,
		MaxAge:                 3 * time.Minute,
		ClaimTTL:               10 * time.Second,
		MaxRebroadcastAttempts: 2,
		DLQStore:               dlqStore,
		Now:                    nowFn,
	}, store, &stubPlanner{}, &stubSigner{}, &stubBroadcaster{}, confirmer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = c.Tick(ctx)
	if err == nil {
		t.Fatal("expected ErrRebroadcastExhausted")
	}
	if !errors.Is(err, ErrRebroadcastExhausted) {
		t.Fatalf("expected ErrRebroadcastExhausted, got %v", err)
	}

	counts, cerr := dlqStore.CountUnacknowledged(ctx)
	if cerr != nil {
		t.Fatalf("CountUnacknowledged: %v", cerr)
	}
	if counts.WithdrawalBatches != 1 {
		t.Fatalf("expected 1 withdrawal batch DLQ entry, got %d", counts.WithdrawalBatches)
	}

	recs, lerr := dlqStore.ListWithdrawalBatchDLQ(ctx, dlq.DLQFilter{})
	if lerr != nil {
		t.Fatalf("ListWithdrawalBatchDLQ: %v", lerr)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 DLQ record, got %d", len(recs))
	}
	if recs[0].FailureStage != "confirm" {
		t.Fatalf("failure_stage: got %q want %q", recs[0].FailureStage, "confirm")
	}
	if recs[0].ErrorCode != "rebroadcast_exhausted" {
		t.Fatalf("error_code: got %q want %q", recs[0].ErrorCode, "rebroadcast_exhausted")
	}
	if recs[0].JunoTxID != "tx-gone" {
		t.Fatalf("juno_tx_id: got %q want %q", recs[0].JunoTxID, "tx-gone")
	}
	if recs[0].RebroadcastAttempts != 2 {
		t.Fatalf("rebroadcast_attempts: got %d want 2", recs[0].RebroadcastAttempts)
	}
}

func TestCoordinator_DLQInsertFailureKeepsRebroadcastRetryable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x92)
	_ = store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})
	_ = store.MarkBatchSigning(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchSigned(ctx, batchID, testWithdrawFence("a"), []byte{0x01})
	_ = store.MarkBatchBroadcastLocked(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchBroadcasted(ctx, batchID, testWithdrawFence("a"), "tx-gone")
	_ = store.SetBatchRebroadcastBackoff(ctx, batchID, testWithdrawFence("a"), 2, now.Add(-1*time.Hour))

	confirmer := &stubConfirmer{errs: []error{ErrConfirmationMissing, ErrConfirmationMissing}}
	dlqStore := newFlakyDLQStore()
	dlqStore.withdrawErrs = []error{errors.New("withdraw dlq unavailable")}

	c, err := newCoordinatorForTest(Config{
		Owner:                  "a",
		MaxItems:               10,
		MaxAge:                 3 * time.Minute,
		ClaimTTL:               10 * time.Second,
		MaxRebroadcastAttempts: 2,
		DLQStore:               dlqStore,
		Now:                    nowFn,
	}, store, &stubPlanner{}, &stubSigner{}, &stubBroadcaster{}, confirmer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = c.Tick(ctx)
	if err == nil {
		t.Fatal("expected dlq persistence error")
	}
	if errors.Is(err, ErrRebroadcastExhausted) {
		t.Fatalf("expected retryable DLQ error, got terminal exhaustion: %v", err)
	}
	if !strings.Contains(err.Error(), "withdrawal batch DLQ") {
		t.Fatalf("expected withdrawal DLQ error, got %v", err)
	}

	counts, cerr := dlqStore.CountUnacknowledged(ctx)
	if cerr != nil {
		t.Fatalf("CountUnacknowledged: %v", cerr)
	}
	if counts.WithdrawalBatches != 0 {
		t.Fatalf("expected no DLQ record after failed insert, got %d", counts.WithdrawalBatches)
	}

	b, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if b.State != withdraw.BatchStateBroadcasted {
		t.Fatalf("expected batch to remain broadcasted, got %s", b.State)
	}
	if b.RebroadcastAttempts != 2 {
		t.Fatalf("rebroadcast attempts: got %d want 2", b.RebroadcastAttempts)
	}

	dlqStore.withdrawErrs = nil
	err = c.Tick(ctx)
	if err == nil {
		t.Fatal("expected ErrRebroadcastExhausted after DLQ recovery")
	}
	if !errors.Is(err, ErrRebroadcastExhausted) {
		t.Fatalf("expected ErrRebroadcastExhausted, got %v", err)
	}

	counts, cerr = dlqStore.CountUnacknowledged(ctx)
	if cerr != nil {
		t.Fatalf("CountUnacknowledged after retry: %v", cerr)
	}
	if counts.WithdrawalBatches != 1 {
		t.Fatalf("expected 1 withdrawal batch DLQ entry after retry, got %d", counts.WithdrawalBatches)
	}
}

type failingSigner struct {
	err error
}

func (s *failingSigner) Sign(_ context.Context, _ [32]byte, _ []byte) ([]byte, error) {
	return nil, s.err
}

func TestCoordinator_DLQ_SigningFailed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x91)
	_ = store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})

	dlqStore := dlq.NewMemoryStore(nil)

	c, err := newCoordinatorForTest(Config{
		Owner:    "a",
		MaxItems: 10,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		DLQStore: dlqStore,
		Now:      nowFn,
	}, store, &stubPlanner{}, &failingSigner{err: errors.New("hsm unavailable")}, &stubBroadcaster{}, &stubConfirmer{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 2; i++ {
		err = c.Tick(ctx)
		if err == nil {
			t.Fatal("expected signing error")
		}
		if !strings.Contains(err.Error(), "hsm unavailable") {
			t.Fatalf("expected signing error, got %v", err)
		}
	}

	if err = c.Tick(ctx); err != nil {
		t.Fatalf("expected no further error after batch DLQ, got %v", err)
	}

	counts, cerr := dlqStore.CountUnacknowledged(ctx)
	if cerr != nil {
		t.Fatalf("CountUnacknowledged: %v", cerr)
	}
	if counts.WithdrawalBatches != 1 {
		t.Fatalf("expected 1 withdrawal batch DLQ entry after repeated failures, got %d", counts.WithdrawalBatches)
	}

	recs, lerr := dlqStore.ListWithdrawalBatchDLQ(ctx, dlq.DLQFilter{})
	if lerr != nil {
		t.Fatalf("ListWithdrawalBatchDLQ: %v", lerr)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 DLQ record, got %d", len(recs))
	}
	if recs[0].FailureStage != "signing" {
		t.Fatalf("failure_stage: got %q want %q", recs[0].FailureStage, "signing")
	}
	if recs[0].ErrorCode != "signing_failed" {
		t.Fatalf("error_code: got %q want %q", recs[0].ErrorCode, "signing_failed")
	}
}

func TestCoordinator_DLQ_NilStoreSkipsDLQ(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, testWithdrawFence("a"), 10*time.Second, 1)
	batchID := seq32(0x92)
	_ = store.CreatePlannedBatch(ctx, testWithdrawFence("a"), withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})
	_ = store.MarkBatchSigning(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchSigned(ctx, batchID, testWithdrawFence("a"), []byte{0x01})
	_ = store.MarkBatchBroadcastLocked(ctx, batchID, testWithdrawFence("a"))
	_ = store.SetBatchBroadcasted(ctx, batchID, testWithdrawFence("a"), "tx-gone")
	_ = store.SetBatchRebroadcastBackoff(ctx, batchID, testWithdrawFence("a"), 5, now.Add(-1*time.Hour))

	confirmer := &stubConfirmer{errs: []error{ErrConfirmationMissing}}

	// No DLQStore configured — should not panic.
	c, err := newCoordinatorForTest(Config{
		Owner:                  "a",
		MaxItems:               10,
		MaxAge:                 3 * time.Minute,
		ClaimTTL:               10 * time.Second,
		MaxRebroadcastAttempts: 5,
		Now:                    nowFn,
	}, store, &stubPlanner{}, &stubSigner{}, &stubBroadcaster{}, confirmer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = c.Tick(ctx)
	if !errors.Is(err, ErrRebroadcastExhausted) {
		t.Fatalf("expected ErrRebroadcastExhausted, got %v", err)
	}
	// No panic, no DLQ store interaction — backwards compatible.
}

func TestCoordinator_LogsBatchLifecycle(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	planner := &stubPlanner{}
	signer := &stubSigner{}
	broadcaster := &stubBroadcaster{}
	confirmer := &stubConfirmer{}

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	c, err := newCoordinatorForTest(Config{
		Owner:    "a",
		MaxItems: 1,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      nowFn,
	}, store, planner, signer, broadcaster, confirmer, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	if err := c.IngestWithdrawRequested(ctx, w); err != nil {
		t.Fatalf("IngestWithdrawRequested: %v", err)
	}

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	output := buf.String()

	wantMessages := []string{
		"batch planned",
		"batch signing",
		"batch signed",
		"batch broadcasting",
		"batch broadcasted",
		"batch confirming",
		"batch confirmed",
	}
	for _, msg := range wantMessages {
		if !strings.Contains(output, msg) {
			t.Errorf("expected log output to contain %q, got:\n%s", msg, output)
		}
	}

	batchID := batching.WithdrawalBatchIDV1([][32]byte{w.ID})
	_ = batchID
	if !strings.Contains(output, "batch_id=") {
		t.Errorf("expected log output to contain batch_id attribute, got:\n%s", output)
	}
}
