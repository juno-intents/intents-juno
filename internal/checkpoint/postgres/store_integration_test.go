//go:build integration

package postgres

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

func TestStore_RecordCommitmentAndListReadyToPin(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"
	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	commitment := checkpoint.SignerCommitment{
		BaseChainID:    8453,
		BridgeContract: common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
		Operator:       common.HexToAddress("0x1111111111111111111111111111111111111111"),
		Height:         123,
		Digest:         common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		SignedAt:       time.Unix(1_700_000_000, 0).UTC(),
	}
	if err := s.RecordCommitment(ctx, commitment); err != nil {
		t.Fatalf("RecordCommitment #1: %v", err)
	}
	if err := s.RecordCommitment(ctx, commitment); err != nil {
		t.Fatalf("RecordCommitment #2: %v", err)
	}

	conflicting := commitment
	conflicting.Digest = common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err := s.RecordCommitment(ctx, conflicting); !errors.Is(err, checkpoint.ErrCheckpointEquivocation) {
		t.Fatalf("expected ErrCheckpointEquivocation, got %v", err)
	}

	now := time.Unix(1_700_000_100, 0).UTC()
	dueDigest := common.HexToHash("0x0101010101010101010101010101010101010101010101010101010101010101")
	futureDigest := common.HexToHash("0x0202020202020202020202020202020202020202020202020202020202020202")
	disabledDigest := common.HexToHash("0x0303030303030303030303030303030303030303030303030303030303030303")

	for _, rec := range []checkpoint.PackageRecord{
		{
			Digest: dueDigest,
			Checkpoint: checkpoint.Checkpoint{
				Height:           200,
				BlockHash:        common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
				FinalOrchardRoot: common.HexToHash("0x1212121212121212121212121212121212121212121212121212121212121212"),
				BaseChainID:      8453,
				BridgeContract:   commitment.BridgeContract,
			},
			OperatorSetHash:  common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			Payload:          []byte(`{"digest":"due"}`),
			PinState:         checkpoint.PackagePinStatePending,
			PinNextAttemptAt: now.Add(-time.Second),
			State:            checkpoint.PackageStateOpen,
			PersistedAt:      now.Add(-2 * time.Second),
		},
		{
			Digest: futureDigest,
			Checkpoint: checkpoint.Checkpoint{
				Height:           201,
				BlockHash:        common.HexToHash("0x2121212121212121212121212121212121212121212121212121212121212121"),
				FinalOrchardRoot: common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
				BaseChainID:      8453,
				BridgeContract:   commitment.BridgeContract,
			},
			OperatorSetHash:  common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			Payload:          []byte(`{"digest":"future"}`),
			PinState:         checkpoint.PackagePinStateFailed,
			PinAttempts:      1,
			PinNextAttemptAt: now.Add(time.Minute),
			State:            checkpoint.PackageStateOpen,
			PersistedAt:      now.Add(-time.Second),
		},
		{
			Digest: disabledDigest,
			Checkpoint: checkpoint.Checkpoint{
				Height:           202,
				BlockHash:        common.HexToHash("0x3131313131313131313131313131313131313131313131313131313131313131"),
				FinalOrchardRoot: common.HexToHash("0x3232323232323232323232323232323232323232323232323232323232323232"),
				BaseChainID:      8453,
				BridgeContract:   commitment.BridgeContract,
			},
			OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			Payload:         []byte(`{"digest":"disabled"}`),
			PinState:        checkpoint.PackagePinStateDisabled,
			State:           checkpoint.PackageStateOpen,
			PersistedAt:     now,
		},
	} {
		if err := s.UpsertPackage(ctx, rec); err != nil {
			t.Fatalf("UpsertPackage(%s): %v", rec.Digest, err)
		}
	}

	ready, err := s.ListReadyToPin(ctx, now, 10)
	if err != nil {
		t.Fatalf("ListReadyToPin: %v", err)
	}
	if len(ready) != 1 {
		t.Fatalf("ready packages: got %d want 1", len(ready))
	}
	if ready[0].Digest != dueDigest {
		t.Fatalf("ready digest: got %s want %s", ready[0].Digest, dueDigest)
	}
}

type integrationBlockingPinner struct {
	cid     string
	started chan struct{}
	release chan struct{}

	mu    sync.Mutex
	calls int
	once  sync.Once
}

func (p *integrationBlockingPinner) PinJSON(_ context.Context, payload []byte) (string, error) {
	_ = payload

	p.mu.Lock()
	p.calls++
	p.mu.Unlock()

	p.once.Do(func() {
		close(p.started)
	})
	<-p.release
	return p.cid, nil
}

func (p *integrationBlockingPinner) CallCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func TestPackagePersistence_ProcessPinJobsClaimsOnlyOneWorker(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"
	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	store, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	pinner := &integrationBlockingPinner{
		cid:     "bafybeigdyrzt",
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	persistA, err := checkpoint.NewPackagePersistence(checkpoint.PackagePersistenceConfig{
		PackageStore: store,
		IPFSPinner:   pinner,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence worker-a: %v", err)
	}
	persistB, err := checkpoint.NewPackagePersistence(checkpoint.PackagePersistenceConfig{
		PackageStore: store,
		IPFSPinner:   pinner,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence worker-b: %v", err)
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := checkpoint.Digest(cp)
	if _, err := persistA.Persist(ctx, checkpoint.PackageEnvelope{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Payload:         []byte(`{"version":"checkpoints.package.v1"}`),
	}); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	done := make(chan struct {
		processed int
		err       error
	}, 1)
	go func() {
		processed, err := persistA.ProcessPinJobs(ctx, "worker-a", time.Minute, 1)
		done <- struct {
			processed int
			err       error
		}{processed: processed, err: err}
	}()

	<-pinner.started

	processed, err := persistB.ProcessPinJobs(ctx, "worker-b", time.Minute, 1)
	if err != nil {
		t.Fatalf("ProcessPinJobs worker-b: %v", err)
	}
	if processed != 0 {
		t.Fatalf("expected worker-b to process 0 jobs, got %d", processed)
	}
	if pinner.CallCount() != 1 {
		t.Fatalf("expected one ipfs call while claim active, got %d", pinner.CallCount())
	}

	close(pinner.release)

	result := <-done
	if result.err != nil {
		t.Fatalf("ProcessPinJobs worker-a: %v", result.err)
	}
	if result.processed != 1 {
		t.Fatalf("expected worker-a to process 1 job, got %d", result.processed)
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
		cctx, cancel := context.WithTimeout(ctx, time.Second)
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
