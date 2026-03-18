package checkpoint

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/blobstore"
)

type fakePinner struct {
	cid     string
	calls   int
	payload []byte
	err     error
}

func (p *fakePinner) PinJSON(_ context.Context, payload []byte) (string, error) {
	p.calls++
	p.payload = append([]byte(nil), payload...)
	if p.err != nil {
		return "", p.err
	}
	return p.cid, nil
}

type blockingPinner struct {
	cid     string
	started chan struct{}
	release chan struct{}

	mu    sync.Mutex
	calls int
	once  sync.Once
}

func (p *blockingPinner) PinJSON(_ context.Context, payload []byte) (string, error) {
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

func (p *blockingPinner) CallCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func TestPackagePersistence_PersistsToAllSinks(t *testing.T) {
	t.Parallel()

	blob, err := blobstore.New(blobstore.Config{Driver: blobstore.DriverMemory})
	if err != nil {
		t.Fatalf("blobstore.New: %v", err)
	}
	store := NewMemoryPackageStore()
	pinner := &fakePinner{cid: "bafybeigdyrzt"}

	now := time.Unix(1_700_000_000, 0).UTC()
	persist, err := NewPackagePersistence(PackagePersistenceConfig{
		PackageStore: store,
		BlobStore:    blob,
		BlobPrefix:   "checkpoint-packages",
		IPFSPinner:   pinner,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence: %v", err)
	}

	cp := Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := Digest(cp)
	payload := []byte(`{"version":"checkpoints.package.v1"}`)

	rec, err := persist.Persist(context.Background(), PackageEnvelope{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Payload:         payload,
	})
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}

	if rec.Digest != digest {
		t.Fatalf("digest: got %s want %s", rec.Digest, digest)
	}
	if rec.State != PackageStateOpen {
		t.Fatalf("state: got %s want %s", rec.State, PackageStateOpen)
	}
	if rec.IPFSCID != "" {
		t.Fatalf("ipfs cid: got %q want empty before background pinning", rec.IPFSCID)
	}
	if rec.PersistedAt != now {
		t.Fatalf("persistedAt: got %s want %s", rec.PersistedAt, now)
	}
	if rec.PinState != PackagePinStatePending {
		t.Fatalf("pin state: got %s want %s", rec.PinState, PackagePinStatePending)
	}
	if pinner.calls != 0 {
		t.Fatalf("ipfs calls: got %d want 0", pinner.calls)
	}

	if rec.BlobKey == "" {
		t.Fatalf("expected non-empty blob key")
	}
	blobObj, err := blob.Get(context.Background(), rec.BlobKey)
	if err != nil {
		t.Fatalf("blob.Get: %v", err)
	}
	if !bytes.Equal(blobObj.Data, payload) {
		t.Fatalf("blob payload mismatch")
	}

	stored, err := store.Get(context.Background(), digest)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if stored.IPFSCID != rec.IPFSCID {
		t.Fatalf("stored ipfs cid: got %q want %q", stored.IPFSCID, rec.IPFSCID)
	}
	if stored.BlobKey != rec.BlobKey {
		t.Fatalf("stored blob key: got %q want %q", stored.BlobKey, rec.BlobKey)
	}
	if stored.PinState != PackagePinStatePending {
		t.Fatalf("stored pin state: got %s want %s", stored.PinState, PackagePinStatePending)
	}
	if stored.State != PackageStateOpen {
		t.Fatalf("stored state: got %s want %s", stored.State, PackageStateOpen)
	}
	if !bytes.Equal(stored.Payload, payload) {
		t.Fatalf("stored payload mismatch")
	}
}

func TestPackagePersistence_RejectsDigestMismatch(t *testing.T) {
	t.Parallel()

	persist, err := NewPackagePersistence(PackagePersistenceConfig{
		PackageStore: NewMemoryPackageStore(),
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence: %v", err)
	}

	cp := Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	_, err = persist.Persist(context.Background(), PackageEnvelope{
		Digest:     common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		Checkpoint: cp,
		Payload:    []byte(`{"version":"checkpoints.package.v1"}`),
	})
	if err == nil {
		t.Fatalf("expected digest mismatch error")
	}
}

func TestPackagePersistence_MarkEmittedTransitionsState(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	store := NewMemoryPackageStore()
	persist, err := NewPackagePersistence(PackagePersistenceConfig{
		PackageStore: store,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence: %v", err)
	}

	cp := Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := Digest(cp)
	payload := []byte(`{"version":"checkpoints.package.v1"}`)

	if _, err := persist.Persist(context.Background(), PackageEnvelope{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Payload:         payload,
	}); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	emittedAt := now.Add(2 * time.Minute).UTC()
	persist.now = func() time.Time { return emittedAt }

	rec, err := persist.MarkEmitted(context.Background(), digest)
	if err != nil {
		t.Fatalf("MarkEmitted: %v", err)
	}

	if rec.State != PackageStateEmitted {
		t.Fatalf("state: got %s want %s", rec.State, PackageStateEmitted)
	}
	if rec.EmittedAt != emittedAt {
		t.Fatalf("emittedAt: got %s want %s", rec.EmittedAt, emittedAt)
	}

	open, err := persist.ListByState(context.Background(), PackageStateOpen)
	if err != nil {
		t.Fatalf("ListByState(open): %v", err)
	}
	if len(open) != 0 {
		t.Fatalf("expected no open records, got %d", len(open))
	}

	emitted, err := persist.ListByState(context.Background(), PackageStateEmitted)
	if err != nil {
		t.Fatalf("ListByState(emitted): %v", err)
	}
	if len(emitted) != 1 {
		t.Fatalf("expected one emitted record, got %d", len(emitted))
	}
	if emitted[0].Digest != digest {
		t.Fatalf("digest: got %s want %s", emitted[0].Digest, digest)
	}
}

func TestPackagePersistence_PersistDoesNotBlockOnIPFSFailure(t *testing.T) {
	t.Parallel()

	store := NewMemoryPackageStore()
	pinner := &fakePinner{err: errors.New("ipfs unavailable")}
	now := time.Unix(1_700_000_000, 0).UTC()

	persist, err := NewPackagePersistence(PackagePersistenceConfig{
		PackageStore: store,
		IPFSPinner:   pinner,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence: %v", err)
	}

	cp := Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := Digest(cp)

	rec, err := persist.Persist(context.Background(), PackageEnvelope{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Payload:         []byte(`{"version":"checkpoints.package.v1"}`),
	})
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if pinner.calls != 0 {
		t.Fatalf("expected no inline ipfs call, got %d", pinner.calls)
	}
	if rec.PinState != PackagePinStatePending {
		t.Fatalf("pin state: got %s want %s", rec.PinState, PackagePinStatePending)
	}
}

func TestPackagePersistence_ProcessPinJobsBacksOffAndRecovers(t *testing.T) {
	t.Parallel()

	store := NewMemoryPackageStore()
	pinner := &fakePinner{err: errors.New("ipfs unavailable")}
	now := time.Unix(1_700_000_000, 0).UTC()

	persist, err := NewPackagePersistence(PackagePersistenceConfig{
		PackageStore: store,
		IPFSPinner:   pinner,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence: %v", err)
	}

	cp := Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := Digest(cp)

	if _, err := persist.Persist(context.Background(), PackageEnvelope{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Payload:         []byte(`{"version":"checkpoints.package.v1"}`),
	}); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	processed, err := persist.ProcessPinJobs(context.Background(), "worker-a", time.Minute, 1)
	if err != nil {
		t.Fatalf("ProcessPinJobs #1: %v", err)
	}
	if processed != 1 {
		t.Fatalf("processed jobs #1: got %d want 1", processed)
	}

	rec, err := store.Get(context.Background(), digest)
	if err != nil {
		t.Fatalf("store.Get #1: %v", err)
	}
	if rec.PinState != PackagePinStateFailed {
		t.Fatalf("pin state after failure: got %s want %s", rec.PinState, PackagePinStateFailed)
	}
	if rec.PinAttempts != 1 {
		t.Fatalf("pin attempts after failure: got %d want 1", rec.PinAttempts)
	}
	if rec.PinClaimOwner != "" || !rec.PinClaimUntil.IsZero() {
		t.Fatalf("expected claim to be cleared after failure, got owner=%q until=%s", rec.PinClaimOwner, rec.PinClaimUntil)
	}
	if rec.PinNextAttemptAt.IsZero() || !rec.PinNextAttemptAt.After(now) {
		t.Fatalf("expected next attempt after %s, got %s", now, rec.PinNextAttemptAt)
	}

	processed, err = persist.ProcessPinJobs(context.Background(), "worker-b", time.Minute, 1)
	if err != nil {
		t.Fatalf("ProcessPinJobs backoff window: %v", err)
	}
	if processed != 0 {
		t.Fatalf("expected no jobs during backoff window, got %d", processed)
	}

	now = rec.PinNextAttemptAt
	pinner.err = nil
	pinner.cid = "bafybeigdyrzt"

	processed, err = persist.ProcessPinJobs(context.Background(), "worker-a", time.Minute, 1)
	if err != nil {
		t.Fatalf("ProcessPinJobs #2: %v", err)
	}
	if processed != 1 {
		t.Fatalf("processed jobs #2: got %d want 1", processed)
	}

	rec, err = store.Get(context.Background(), digest)
	if err != nil {
		t.Fatalf("store.Get #2: %v", err)
	}
	if rec.PinState != PackagePinStatePinned {
		t.Fatalf("pin state after success: got %s want %s", rec.PinState, PackagePinStatePinned)
	}
	if rec.IPFSCID != pinner.cid {
		t.Fatalf("ipfs cid: got %q want %q", rec.IPFSCID, pinner.cid)
	}
	if rec.PinAttempts != 2 {
		t.Fatalf("pin attempts after success: got %d want 2", rec.PinAttempts)
	}
	if rec.PinClaimOwner != "" || !rec.PinClaimUntil.IsZero() {
		t.Fatalf("expected claim to be cleared after success, got owner=%q until=%s", rec.PinClaimOwner, rec.PinClaimUntil)
	}
}

func TestPackagePersistence_ProcessPinJobs_ClaimsPerWorkerWindow(t *testing.T) {
	t.Parallel()

	store := NewMemoryPackageStore()
	pinner := &blockingPinner{
		cid:     "bafybeigdyrzt",
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	now := time.Unix(1_700_000_000, 0).UTC()

	persistA, err := NewPackagePersistence(PackagePersistenceConfig{
		PackageStore: store,
		IPFSPinner:   pinner,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence worker-a: %v", err)
	}
	persistB, err := NewPackagePersistence(PackagePersistenceConfig{
		PackageStore: store,
		IPFSPinner:   pinner,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence worker-b: %v", err)
	}

	cp := Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := Digest(cp)

	if _, err := persistA.Persist(context.Background(), PackageEnvelope{
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
		processed, err := persistA.ProcessPinJobs(context.Background(), "worker-a", time.Minute, 1)
		done <- struct {
			processed int
			err       error
		}{processed: processed, err: err}
	}()

	<-pinner.started

	processed, err := persistB.ProcessPinJobs(context.Background(), "worker-b", time.Minute, 1)
	if err != nil {
		t.Fatalf("ProcessPinJobs worker-b: %v", err)
	}
	if processed != 0 {
		t.Fatalf("expected worker-b to see no claimable jobs, got %d", processed)
	}
	if pinner.CallCount() != 1 {
		t.Fatalf("expected exactly one ipfs call while claim active, got %d", pinner.CallCount())
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

func TestMemoryPackageStore_ClaimReadyToPin_RespectsLimitBeforeClaiming(t *testing.T) {
	t.Parallel()

	store := NewMemoryPackageStore()
	now := time.Unix(1_700_000_000, 0).UTC()
	baseCheckpoint := Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}

	for i, payload := range []string{`{"digest":"first"}`, `{"digest":"second"}`} {
		cp := baseCheckpoint
		cp.Height += uint64(i)
		if i == 1 {
			cp.BlockHash = common.HexToHash("0x2102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
		}
		rec := PackageRecord{
			Digest:           Digest(cp),
			Checkpoint:       cp,
			OperatorSetHash:  common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			Payload:          []byte(payload),
			PinState:         PackagePinStatePending,
			PinNextAttemptAt: now,
			State:            PackageStateOpen,
			PersistedAt:      now.Add(time.Duration(i) * time.Second),
		}
		if err := store.UpsertPackage(context.Background(), rec); err != nil {
			t.Fatalf("UpsertPackage(%d): %v", i, err)
		}
	}

	claimed, err := store.ClaimReadyToPin(context.Background(), "worker-a", time.Minute, now, 1)
	if err != nil {
		t.Fatalf("ClaimReadyToPin worker-a: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("claimed count: got %d want 1", len(claimed))
	}

	secondClaim, err := store.ClaimReadyToPin(context.Background(), "worker-b", time.Minute, now, 1)
	if err != nil {
		t.Fatalf("ClaimReadyToPin worker-b: %v", err)
	}
	if len(secondClaim) != 1 {
		t.Fatalf("second claim count: got %d want 1", len(secondClaim))
	}
	if secondClaim[0].Digest == claimed[0].Digest {
		t.Fatalf("expected different package on second claim, got same digest %s", secondClaim[0].Digest)
	}
}
