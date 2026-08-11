//go:build integration

package withdrawcoordinator

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/batching"
	"github.com/juno-intents/intents-juno/internal/leases"
	leasespg "github.com/juno-intents/intents-juno/internal/leases/postgres"
	"github.com/juno-intents/intents-juno/internal/withdraw"
	withdrawpg "github.com/juno-intents/intents-juno/internal/withdraw/postgres"
)

type integPlanner struct {
	calls atomic.Int32
}

func (p *integPlanner) Plan(_ context.Context, _ [32]byte, _ []withdraw.Withdrawal) ([]byte, error) {
	p.calls.Add(1)
	return []byte(`{"v":1}`), nil
}

type integSigner struct{}

func (s *integSigner) Sign(_ context.Context, _ [32]byte, _ []byte) ([]byte, error) {
	return []byte{0x01}, nil
}

type integBroadcaster struct{}

func (b *integBroadcaster) Broadcast(_ context.Context, _ []byte) (string, error) { return "tx1", nil }

type integConfirmer struct{}

func (c *integConfirmer) WaitConfirmed(_ context.Context, _ string) error { return nil }

type blockingIntegPlanner struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func newBlockingIntegPlanner() *blockingIntegPlanner {
	return &blockingIntegPlanner{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
}

func (p *blockingIntegPlanner) Plan(ctx context.Context, _ [32]byte, _ []withdraw.Withdrawal) ([]byte, error) {
	p.calls.Add(1)
	select {
	case p.started <- struct{}{}:
	default:
	}
	select {
	case <-p.release:
		return []byte(`{"v":1}`), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type integrationLeaderRun struct {
	ran bool
	err error
}

func TestCoordinator_Integration_PostgresStore(t *testing.T) {
	ctx, _, store, _ := newCoordinatorIntegrationStores(t)

	now := time.Now().UTC()

	c, err := newCoordinatorForTest(Config{
		Owner:    "a",
		MaxItems: 2,
		MaxAge:   3 * time.Minute,
		ClaimTTL: 10 * time.Second,
		Now:      time.Now,
	}, store, &integPlanner{}, &integSigner{}, &integBroadcaster{}, &integConfirmer{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	w0 := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	w1 := withdraw.Withdrawal{ID: seq32(0x20), Amount: 2, FeeBps: 0, RecipientUA: []byte{0x02}, Expiry: now.Add(24 * time.Hour)}

	if err := c.IngestWithdrawRequested(ctx, w0); err != nil {
		t.Fatalf("IngestWithdrawRequested w0: %v", err)
	}
	if err := c.IngestWithdrawRequested(ctx, w1); err != nil {
		t.Fatalf("IngestWithdrawRequested w1: %v", err)
	}

	if err := c.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	confirmed, err := store.ListBatchesByState(ctx, withdraw.BatchStateConfirmed)
	if err != nil {
		t.Fatalf("ListBatchesByState: %v", err)
	}
	if len(confirmed) != 1 {
		t.Fatalf("expected 1 confirmed batch, got %d", len(confirmed))
	}
}

func TestCoordinator_Integration_LeaderHeartbeatPersistsExactlyOneBatch(t *testing.T) {
	ctx, pool, store, leaseStore := newCoordinatorIntegrationStores(t)

	const leaseName = "withdraw-coordinator-integration-heartbeat"
	leaseTTL := 900 * time.Millisecond
	now := time.Now().UTC()
	w := withdraw.Withdrawal{
		ID:          seq32(0x40),
		Amount:      3,
		RecipientUA: []byte{0x03},
		Expiry:      now.Add(24 * time.Hour),
	}

	plannerA := newBlockingIntegPlanner()
	plannerB := &integPlanner{}
	coordinatorA := newIntegrationCoordinator(t, store, leaseStore, "coordinator-a", plannerA)
	coordinatorB := newIntegrationCoordinator(t, store, leaseStore, "coordinator-b", plannerB)
	if err := coordinatorA.IngestWithdrawRequested(ctx, w); err != nil {
		t.Fatalf("IngestWithdrawRequested: %v", err)
	}

	electorA, err := NewLeaderElector(leaseStore, leaseName, "coordinator-a", leaseTTL)
	if err != nil {
		t.Fatalf("NewLeaderElector coordinator-a: %v", err)
	}
	electorB, err := NewLeaderElector(leaseStore, leaseName, "coordinator-b", leaseTTL)
	if err != nil {
		t.Fatalf("NewLeaderElector coordinator-b: %v", err)
	}

	initialLeaseCh := make(chan leases.Lease, 1)
	runACh := make(chan integrationLeaderRun, 1)
	go func() {
		ran, runErr := electorA.RunWhileLeader(ctx, func(workCtx context.Context, lease leases.Lease) error {
			initialLeaseCh <- lease
			coordinatorA.SetLeaderLease(lease)
			defer coordinatorA.ClearLeaderLease()
			return coordinatorA.Tick(workCtx)
		})
		runACh <- integrationLeaderRun{ran: ran, err: runErr}
	}()

	var initialLease leases.Lease
	select {
	case initialLease = <-initialLeaseCh:
	case <-ctx.Done():
		t.Fatalf("coordinator-a did not acquire leadership: %v", ctx.Err())
	}
	select {
	case <-plannerA.started:
	case <-ctx.Done():
		t.Fatalf("coordinator-a planner did not start: %v", ctx.Err())
	}

	// Wait until the original lease would have expired. The work must still be
	// running under the same fence, with a later expiry persisted by heartbeat.
	renewedLease, dbNow := waitForIntegrationLease(t, ctx, leaseStore, leaseName, func(current leases.Lease, currentDBTime time.Time) bool {
		return !currentDBTime.Before(initialLease.ExpiresAt) &&
			current.Owner == initialLease.Owner &&
			current.Version == initialLease.Version &&
			current.ExpiresAt.After(currentDBTime)
	})
	if !renewedLease.ExpiresAt.After(initialLease.ExpiresAt) {
		t.Fatalf("heartbeat did not extend lease expiry: initial=%s renewed=%s db_now=%s", initialLease.ExpiresAt, renewedLease.ExpiresAt, dbNow)
	}

	followerCallbackRan := false
	ranB, err := electorB.RunWhileLeader(ctx, func(context.Context, leases.Lease) error {
		followerCallbackRan = true
		return nil
	})
	if err != nil {
		t.Fatalf("coordinator-b follower attempt: %v", err)
	}
	if ranB || followerCallbackRan {
		t.Fatalf("coordinator-b ran while coordinator-a held renewed fence: ran=%t callback=%t", ranB, followerCallbackRan)
	}

	close(plannerA.release)
	select {
	case result := <-runACh:
		if result.err != nil {
			t.Fatalf("coordinator-a run: %v", result.err)
		}
		if !result.ran {
			t.Fatal("coordinator-a did not run as leader")
		}
	case <-ctx.Done():
		t.Fatalf("coordinator-a did not finish: %v", ctx.Err())
	}

	batchID := batching.WithdrawalBatchIDV1([][32]byte{w.ID})
	batch, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if batch.State != withdraw.BatchStateConfirmed {
		t.Fatalf("batch state: got %s want %s", batch.State, withdraw.BatchStateConfirmed)
	}
	if len(batch.WithdrawalIDs) != 1 || batch.WithdrawalIDs[0] != w.ID {
		t.Fatalf("batch membership: got %x want only %x", batch.WithdrawalIDs, w.ID)
	}
	if batch.LeaseOwner != initialLease.Owner || batch.LeaseVersion != initialLease.Version {
		t.Fatalf("batch fence: got owner=%q version=%d want owner=%q version=%d", batch.LeaseOwner, batch.LeaseVersion, initialLease.Owner, initialLease.Version)
	}
	assertIntegrationBatchCount(t, ctx, pool, 1)

	// RunWhileLeader intentionally leaves the lease to expire. Once it does,
	// coordinator-b must be able to take over, find no duplicate work, and
	// preserve the single durable batch.
	waitForIntegrationLease(t, ctx, leaseStore, leaseName, func(current leases.Lease, currentDBTime time.Time) bool {
		return !current.ExpiresAt.After(currentDBTime)
	})

	ranB, err = electorB.RunWhileLeader(ctx, func(workCtx context.Context, lease leases.Lease) error {
		coordinatorB.SetLeaderLease(lease)
		defer coordinatorB.ClearLeaderLease()
		return coordinatorB.Tick(workCtx)
	})
	if err != nil {
		t.Fatalf("coordinator-b takeover: %v", err)
	}
	if !ranB {
		t.Fatal("coordinator-b was starved after coordinator-a lease expired")
	}
	if got := plannerA.calls.Load(); got != 1 {
		t.Fatalf("coordinator-a planner calls: got %d want 1", got)
	}
	if got := plannerB.calls.Load(); got != 0 {
		t.Fatalf("coordinator-b duplicated planning: got %d planner calls want 0", got)
	}
	assertIntegrationBatchCount(t, ctx, pool, 1)
}

func newCoordinatorIntegrationStores(t *testing.T) (context.Context, *pgxpool.Pool, *withdrawpg.Store, *leasespg.Store) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	// Pin for deterministic integration tests.
	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	store, err := withdrawpg.New(pool)
	if err != nil {
		t.Fatalf("withdrawpg.New: %v", err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("withdraw EnsureSchema: %v", err)
	}

	leaseStore, err := leasespg.New(pool)
	if err != nil {
		t.Fatalf("leasespg.New: %v", err)
	}
	if err := leaseStore.EnsureSchema(ctx); err != nil {
		t.Fatalf("leases EnsureSchema: %v", err)
	}
	return ctx, pool, store, leaseStore
}

func newIntegrationCoordinator(t *testing.T, store withdraw.Store, leaseStore leases.Store, owner string, planner Planner) *Coordinator {
	t.Helper()
	coordinator, err := newCoordinatorForTest(Config{
		Owner:            owner,
		MaxItems:         1,
		MaxAge:           3 * time.Minute,
		ClaimTTL:         10 * time.Second,
		LeaderLeaseStore: leaseStore,
		Now:              time.Now,
	}, store, planner, &integSigner{}, &integBroadcaster{}, &integConfirmer{}, nil)
	if err != nil {
		t.Fatalf("New coordinator %q: %v", owner, err)
	}
	return coordinator
}

func waitForIntegrationLease(t *testing.T, ctx context.Context, store *leasespg.Store, name string, predicate func(leases.Lease, time.Time) bool) (leases.Lease, time.Time) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	var (
		lastLease leases.Lease
		lastDBNow time.Time
		lastErr   error
	)
	for {
		lastLease, lastDBNow, lastErr = store.GetWithStoreTime(ctx, name)
		if lastErr == nil && predicate(lastLease, lastDBNow) {
			return lastLease, lastDBNow
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for lease %q: %v (last lease=%+v db_now=%s store_err=%v)", name, ctx.Err(), lastLease, lastDBNow, lastErr)
		case <-deadline.C:
			t.Fatalf("waiting for lease %q: timeout (last lease=%+v db_now=%s store_err=%v)", name, lastLease, lastDBNow, lastErr)
		case <-ticker.C:
		}
	}
}

func assertIntegrationBatchCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM withdrawal_batches`).Scan(&got); err != nil {
		t.Fatalf("count withdrawal_batches: %v", err)
	}
	if got != want {
		t.Fatalf("withdrawal batch count: got %d want %d", got, want)
	}
}

func mustFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:")
}

func dockerRunPostgres(t *testing.T, ctx context.Context, image string, hostPort string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker",
		"run",
		"--rm",
		"-d",
		"-e", "POSTGRES_USER=postgres",
		"-e", "POSTGRES_PASSWORD=postgres",
		"-e", "POSTGRES_DB=postgres",
		"-p", "127.0.0.1:"+hostPort+":5432",
		image,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run postgres: %v: %s", err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func dialPostgres(t *testing.T, ctx context.Context, dsn string) *pgxpool.Pool {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		cctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		pool, err := pgxpool.New(cctx, dsn)
		if err == nil {
			if err := pool.Ping(cctx); err == nil {
				cancel()
				return pool
			}
			pool.Close()
		}
		cancel()
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("postgres not ready: %s", dsn)
	return nil
}
