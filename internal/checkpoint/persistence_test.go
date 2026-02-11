package checkpoint

import (
	"bytes"
	"context"
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
	if rec.IPFSCID != pinner.cid {
		t.Fatalf("ipfs cid: got %q want %q", rec.IPFSCID, pinner.cid)
	}
	if rec.PersistedAt != now {
		t.Fatalf("persistedAt: got %s want %s", rec.PersistedAt, now)
	}
	if pinner.calls != 1 {
		t.Fatalf("ipfs calls: got %d want 1", pinner.calls)
	}
	if !bytes.Equal(pinner.payload, payload) {
		t.Fatalf("ipfs payload mismatch")
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
