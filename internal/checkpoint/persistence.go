package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/blobstore"
)

var (
	ErrInvalidPersistenceConfig = errors.New("checkpoint: invalid persistence config")
	ErrInvalidPackageEnvelope   = errors.New("checkpoint: invalid package envelope")
	ErrPackageNotFound          = errors.New("checkpoint: package not found")
)

// PackageStore persists checkpoint package metadata and payload references.
type PackageStore interface {
	UpsertPackage(ctx context.Context, rec PackageRecord) error
}

// IPFSPinner pins a package payload and returns the resulting CID.
type IPFSPinner interface {
	PinJSON(ctx context.Context, payload []byte) (string, error)
}

// PackageEnvelope contains the immutable payload plus fields used for persistence indexes.
type PackageEnvelope struct {
	Digest          common.Hash
	Checkpoint      Checkpoint
	OperatorSetHash common.Hash
	Payload         []byte
}

// PackageRecord is the persisted representation of a checkpoint package.
type PackageRecord struct {
	Digest          common.Hash
	Checkpoint      Checkpoint
	OperatorSetHash common.Hash
	Payload         []byte
	IPFSCID         string
	BlobKey         string
	PersistedAt     time.Time
}

type PackagePersistenceConfig struct {
	PackageStore PackageStore
	BlobStore    blobstore.Store
	BlobPrefix   string
	IPFSPinner   IPFSPinner
	Now          func() time.Time
}

type PackagePersistence struct {
	store      PackageStore
	blobStore  blobstore.Store
	blobPrefix string
	ipfs       IPFSPinner
	now        func() time.Time
}

func NewPackagePersistence(cfg PackagePersistenceConfig) (*PackagePersistence, error) {
	if cfg.PackageStore == nil && cfg.BlobStore == nil && cfg.IPFSPinner == nil {
		return nil, fmt.Errorf("%w: at least one sink must be configured", ErrInvalidPersistenceConfig)
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &PackagePersistence{
		store:      cfg.PackageStore,
		blobStore:  cfg.BlobStore,
		blobPrefix: normalizePrefix(cfg.BlobPrefix),
		ipfs:       cfg.IPFSPinner,
		now:        nowFn,
	}, nil
}

func (p *PackagePersistence) Persist(ctx context.Context, env PackageEnvelope) (PackageRecord, error) {
	if len(env.Payload) == 0 {
		return PackageRecord{}, fmt.Errorf("%w: empty payload", ErrInvalidPackageEnvelope)
	}
	if env.Digest == (common.Hash{}) {
		return PackageRecord{}, fmt.Errorf("%w: empty digest", ErrInvalidPackageEnvelope)
	}
	if got := Digest(env.Checkpoint); got != env.Digest {
		return PackageRecord{}, fmt.Errorf("%w: digest mismatch: computed %s got %s", ErrInvalidPackageEnvelope, got, env.Digest)
	}

	rec := PackageRecord{
		Digest:          env.Digest,
		Checkpoint:      env.Checkpoint,
		OperatorSetHash: env.OperatorSetHash,
		Payload:         append([]byte(nil), env.Payload...),
		PersistedAt:     p.now().UTC(),
	}

	if p.blobStore != nil {
		rec.BlobKey = packageBlobKey(p.blobPrefix, env.Checkpoint.BaseChainID, env.Digest)
		if err := p.blobStore.Put(ctx, rec.BlobKey, env.Payload, blobstore.PutOptions{
			ContentType: "application/json",
			Metadata: map[string]string{
				"digest":            env.Digest.Hex(),
				"base_chain_id":     fmt.Sprintf("%d", env.Checkpoint.BaseChainID),
				"bridge_contract":   env.Checkpoint.BridgeContract.Hex(),
				"operator_set_hash": env.OperatorSetHash.Hex(),
			},
		}); err != nil {
			return PackageRecord{}, err
		}
	}

	if p.ipfs != nil {
		cid, err := p.ipfs.PinJSON(ctx, env.Payload)
		if err != nil {
			return PackageRecord{}, err
		}
		rec.IPFSCID = strings.TrimSpace(cid)
	}

	if p.store != nil {
		if err := p.store.UpsertPackage(ctx, rec); err != nil {
			return PackageRecord{}, err
		}
	}
	return rec, nil
}

func packageBlobKey(prefix string, baseChainID uint64, digest common.Hash) string {
	d := strings.TrimPrefix(strings.ToLower(digest.Hex()), "0x")
	key := fmt.Sprintf("%d/%s.json", baseChainID, d)
	if prefix == "" {
		return key
	}
	return prefix + "/" + key
}

func normalizePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	return strings.Trim(prefix, "/")
}

type MemoryPackageStore struct {
	mu      sync.Mutex
	records map[common.Hash]PackageRecord
}

func NewMemoryPackageStore() *MemoryPackageStore {
	return &MemoryPackageStore{records: make(map[common.Hash]PackageRecord)}
}

func (s *MemoryPackageStore) UpsertPackage(_ context.Context, rec PackageRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[rec.Digest] = clonePackageRecord(rec)
	return nil
}

func (s *MemoryPackageStore) Get(_ context.Context, digest common.Hash) (PackageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[digest]
	if !ok {
		return PackageRecord{}, ErrPackageNotFound
	}
	return clonePackageRecord(rec), nil
}

func clonePackageRecord(rec PackageRecord) PackageRecord {
	out := rec
	out.Payload = append([]byte(nil), rec.Payload...)
	return out
}

var _ PackageStore = (*MemoryPackageStore)(nil)
