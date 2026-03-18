package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"sort"
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
	Get(ctx context.Context, digest common.Hash) (PackageRecord, error)
	ListByState(ctx context.Context, state PackageState) ([]PackageRecord, error)
	ListReadyToPin(ctx context.Context, now time.Time, limit int) ([]PackageRecord, error)
	ClaimReadyToPin(ctx context.Context, owner string, claimTTL time.Duration, now time.Time, limit int) ([]PackageRecord, error)
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
	Digest           common.Hash
	Checkpoint       Checkpoint
	OperatorSetHash  common.Hash
	Payload          []byte
	IPFSCID          string
	BlobKey          string
	PinState         PackagePinState
	PinAttempts      int
	PinLastError     string
	PinLastAttemptAt time.Time
	PinNextAttemptAt time.Time
	PinClaimOwner    string
	PinClaimUntil    time.Time
	State            PackageState
	PersistedAt      time.Time
	EmittedAt        time.Time
}

type PackageState uint8

const (
	PackageStateUnknown PackageState = iota
	PackageStateOpen
	PackageStateEmitted
)

func (s PackageState) String() string {
	switch s {
	case PackageStateOpen:
		return "open"
	case PackageStateEmitted:
		return "emitted"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

type PackagePinState uint8

const (
	PackagePinStateUnknown PackagePinState = iota
	PackagePinStateDisabled
	PackagePinStatePending
	PackagePinStatePinned
	PackagePinStateFailed
)

func (s PackagePinState) String() string {
	switch s {
	case PackagePinStateDisabled:
		return "disabled"
	case PackagePinStatePending:
		return "pending"
	case PackagePinStatePinned:
		return "pinned"
	case PackagePinStateFailed:
		return "failed"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

type PackagePersistenceConfig struct {
	PackageStore      PackageStore
	BlobStore         blobstore.Store
	BlobPrefix        string
	IPFSPinner        IPFSPinner
	PinRetryBaseDelay time.Duration
	Now               func() time.Time
}

type PackagePersistence struct {
	store             PackageStore
	blobStore         blobstore.Store
	blobPrefix        string
	ipfs              IPFSPinner
	pinRetryBaseDelay time.Duration
	now               func() time.Time
}

func NewPackagePersistence(cfg PackagePersistenceConfig) (*PackagePersistence, error) {
	if cfg.PackageStore == nil && cfg.BlobStore == nil && cfg.IPFSPinner == nil {
		return nil, fmt.Errorf("%w: at least one sink must be configured", ErrInvalidPersistenceConfig)
	}
	if cfg.IPFSPinner != nil && cfg.PackageStore == nil {
		return nil, fmt.Errorf("%w: package store required when ipfs pinning is enabled", ErrInvalidPersistenceConfig)
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	pinRetryBaseDelay := cfg.PinRetryBaseDelay
	if pinRetryBaseDelay <= 0 {
		pinRetryBaseDelay = 30 * time.Second
	}
	return &PackagePersistence{
		store:             cfg.PackageStore,
		blobStore:         cfg.BlobStore,
		blobPrefix:        normalizePrefix(cfg.BlobPrefix),
		ipfs:              cfg.IPFSPinner,
		pinRetryBaseDelay: pinRetryBaseDelay,
		now:               nowFn,
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
		State:           PackageStateOpen,
		PersistedAt:     p.now().UTC(),
		PinState:        PackagePinStateDisabled,
	}
	if p.ipfs != nil {
		rec.PinState = PackagePinStatePending
		rec.PinNextAttemptAt = rec.PersistedAt
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

	if p.store != nil {
		if err := p.store.UpsertPackage(ctx, rec); err != nil {
			return PackageRecord{}, err
		}
	}
	return rec, nil
}

func (p *PackagePersistence) MarkEmitted(ctx context.Context, digest common.Hash) (PackageRecord, error) {
	if p == nil || p.store == nil {
		return PackageRecord{}, fmt.Errorf("%w: package store required to mark emitted", ErrInvalidPersistenceConfig)
	}
	rec, err := p.store.Get(ctx, digest)
	if err != nil {
		return PackageRecord{}, err
	}
	rec.State = PackageStateEmitted
	rec.EmittedAt = p.now().UTC()
	if err := p.store.UpsertPackage(ctx, rec); err != nil {
		return PackageRecord{}, err
	}
	return rec, nil
}

func (p *PackagePersistence) ListByState(ctx context.Context, state PackageState) ([]PackageRecord, error) {
	if p == nil || p.store == nil {
		return nil, fmt.Errorf("%w: package store required to list by state", ErrInvalidPersistenceConfig)
	}
	return p.store.ListByState(ctx, state)
}

func (p *PackagePersistence) Get(ctx context.Context, digest common.Hash) (PackageRecord, error) {
	if p == nil || p.store == nil {
		return PackageRecord{}, fmt.Errorf("%w: package store required to get package", ErrInvalidPersistenceConfig)
	}
	return p.store.Get(ctx, digest)
}

func (p *PackagePersistence) ProcessPinJobs(ctx context.Context, owner string, claimTTL time.Duration, limit int) (int, error) {
	if p == nil || p.ipfs == nil {
		return 0, nil
	}
	if p.store == nil {
		return 0, fmt.Errorf("%w: package store required to process pin jobs", ErrInvalidPersistenceConfig)
	}
	if limit <= 0 {
		return 0, nil
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return 0, fmt.Errorf("%w: pin claim owner is required", ErrInvalidPersistenceConfig)
	}
	if claimTTL <= 0 {
		claimTTL = time.Minute
	}

	recs, err := p.store.ClaimReadyToPin(ctx, owner, claimTTL, p.now().UTC(), limit)
	if err != nil {
		return 0, err
	}

	processed := 0
	for _, rec := range recs {
		attemptedAt := p.now().UTC()
		cid, err := p.ipfs.PinJSON(ctx, rec.Payload)
		rec.PinAttempts++
		rec.PinLastAttemptAt = attemptedAt
		if err != nil {
			rec.PinState = PackagePinStateFailed
			rec.PinLastError = pinErrorString(err)
			rec.PinNextAttemptAt = attemptedAt.Add(p.pinRetryDelay(rec.PinAttempts))
			rec.PinClaimOwner = ""
			rec.PinClaimUntil = time.Time{}
			if upsertErr := p.store.UpsertPackage(ctx, rec); upsertErr != nil {
				return processed, upsertErr
			}
			processed++
			continue
		}

		cid = strings.TrimSpace(cid)
		if cid == "" {
			rec.PinState = PackagePinStateFailed
			rec.PinLastError = "checkpoint/ipfs: empty cid in response"
			rec.PinNextAttemptAt = attemptedAt.Add(p.pinRetryDelay(rec.PinAttempts))
			rec.PinClaimOwner = ""
			rec.PinClaimUntil = time.Time{}
			if upsertErr := p.store.UpsertPackage(ctx, rec); upsertErr != nil {
				return processed, upsertErr
			}
			processed++
			continue
		}

		rec.IPFSCID = cid
		rec.PinState = PackagePinStatePinned
		rec.PinLastError = ""
		rec.PinNextAttemptAt = time.Time{}
		rec.PinClaimOwner = ""
		rec.PinClaimUntil = time.Time{}
		if upsertErr := p.store.UpsertPackage(ctx, rec); upsertErr != nil {
			return processed, upsertErr
		}
		processed++
	}
	return processed, nil
}

func (p *PackagePersistence) pinRetryDelay(attempts int) time.Duration {
	if attempts <= 0 {
		return p.pinRetryBaseDelay
	}
	delay := p.pinRetryBaseDelay
	for i := 1; i < attempts; i++ {
		if delay >= 15*time.Minute {
			return 15 * time.Minute
		}
		delay *= 2
	}
	if delay > 15*time.Minute {
		return 15 * time.Minute
	}
	return delay
}

func pinErrorString(err error) string {
	return strings.TrimSpace(err.Error())
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

func (s *MemoryPackageStore) ListByState(_ context.Context, state PackageState) ([]PackageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]PackageRecord, 0, len(s.records))
	for _, rec := range s.records {
		if rec.State == state {
			out = append(out, clonePackageRecord(rec))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PersistedAt.Equal(out[j].PersistedAt) {
			return out[i].Digest.Hex() < out[j].Digest.Hex()
		}
		return out[i].PersistedAt.Before(out[j].PersistedAt)
	})
	return out, nil
}

func (s *MemoryPackageStore) ListReadyToPin(_ context.Context, now time.Time, limit int) ([]PackageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]PackageRecord, 0, len(s.records))
	for _, rec := range s.records {
		if rec.PinState != PackagePinStatePending && rec.PinState != PackagePinStateFailed {
			continue
		}
		if !rec.PinNextAttemptAt.IsZero() && rec.PinNextAttemptAt.After(now) {
			continue
		}
		out = append(out, clonePackageRecord(rec))
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].PinNextAttemptAt
		right := out[j].PinNextAttemptAt
		switch {
		case left.Equal(right):
			if out[i].PersistedAt.Equal(out[j].PersistedAt) {
				return out[i].Digest.Hex() < out[j].Digest.Hex()
			}
			return out[i].PersistedAt.Before(out[j].PersistedAt)
		case left.IsZero():
			return true
		case right.IsZero():
			return false
		default:
			return left.Before(right)
		}
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryPackageStore) ClaimReadyToPin(_ context.Context, owner string, claimTTL time.Duration, now time.Time, limit int) ([]PackageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 {
		return nil, nil
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil, fmt.Errorf("%w: pin claim owner is required", ErrInvalidPersistenceConfig)
	}
	if claimTTL <= 0 {
		claimTTL = time.Minute
	}

	out := make([]PackageRecord, 0, len(s.records))
	for digest, rec := range s.records {
		if rec.PinState != PackagePinStatePending && rec.PinState != PackagePinStateFailed {
			continue
		}
		if !rec.PinNextAttemptAt.IsZero() && rec.PinNextAttemptAt.After(now) {
			continue
		}
		if rec.PinClaimOwner != "" && !rec.PinClaimUntil.IsZero() && rec.PinClaimUntil.After(now) {
			continue
		}
		rec.PinClaimOwner = owner
		rec.PinClaimUntil = now.Add(claimTTL)
		s.records[digest] = clonePackageRecord(rec)
		out = append(out, clonePackageRecord(rec))
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].PinNextAttemptAt
		right := out[j].PinNextAttemptAt
		switch {
		case left.Equal(right):
			if out[i].PersistedAt.Equal(out[j].PersistedAt) {
				return out[i].Digest.Hex() < out[j].Digest.Hex()
			}
			return out[i].PersistedAt.Before(out[j].PersistedAt)
		case left.IsZero():
			return true
		case right.IsZero():
			return false
		default:
			return left.Before(right)
		}
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func clonePackageRecord(rec PackageRecord) PackageRecord {
	out := rec
	out.Payload = append([]byte(nil), rec.Payload...)
	return out
}

var _ PackageStore = (*MemoryPackageStore)(nil)
