package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

var ErrInvalidConfig = errors.New("checkpoint/postgres: invalid config")

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: nil pool", ErrInvalidConfig)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) EnsureSchema(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if _, err := s.pool.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("checkpoint/postgres: ensure schema: %w", err)
	}
	return nil
}

func (s *Store) UpsertPackage(ctx context.Context, rec checkpoint.PackageRecord) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if rec.Digest == (common.Hash{}) || len(rec.Payload) == 0 {
		return fmt.Errorf("%w: missing digest/payload", checkpoint.ErrInvalidPackageEnvelope)
	}

	persistedAt := rec.PersistedAt
	if persistedAt.IsZero() {
		persistedAt = time.Now().UTC()
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO checkpoint_packages (
			digest,
			checkpoint_height,
			checkpoint_block_hash,
			checkpoint_final_orchard_root,
			checkpoint_base_chain_id,
			checkpoint_bridge_contract,
			operator_set_hash,
			ipfs_cid,
			s3_key,
			package_json,
			persisted_at,
			updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())
		ON CONFLICT (digest) DO UPDATE
		SET
			checkpoint_height = EXCLUDED.checkpoint_height,
			checkpoint_block_hash = EXCLUDED.checkpoint_block_hash,
			checkpoint_final_orchard_root = EXCLUDED.checkpoint_final_orchard_root,
			checkpoint_base_chain_id = EXCLUDED.checkpoint_base_chain_id,
			checkpoint_bridge_contract = EXCLUDED.checkpoint_bridge_contract,
			operator_set_hash = EXCLUDED.operator_set_hash,
			ipfs_cid = EXCLUDED.ipfs_cid,
			s3_key = EXCLUDED.s3_key,
			package_json = EXCLUDED.package_json,
			persisted_at = EXCLUDED.persisted_at,
			updated_at = now()
	`,
		rec.Digest[:],
		int64(rec.Checkpoint.Height),
		rec.Checkpoint.BlockHash[:],
		rec.Checkpoint.FinalOrchardRoot[:],
		int64(rec.Checkpoint.BaseChainID),
		rec.Checkpoint.BridgeContract[:],
		rec.OperatorSetHash[:],
		nullableString(rec.IPFSCID),
		nullableString(rec.BlobKey),
		rec.Payload,
		persistedAt,
	)
	if err != nil {
		return fmt.Errorf("checkpoint/postgres: upsert package: %w", err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, digest common.Hash) (checkpoint.PackageRecord, error) {
	if s == nil || s.pool == nil {
		return checkpoint.PackageRecord{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if digest == (common.Hash{}) {
		return checkpoint.PackageRecord{}, checkpoint.ErrInvalidPackageEnvelope
	}

	var (
		digestRaw    []byte
		height       int64
		blockHashRaw []byte
		rootRaw      []byte
		baseChainID  int64
		bridgeRaw    []byte
		opSetHashRaw []byte
		ipfsCID      *string
		blobKey      *string
		payload      []byte
		persistedAt  time.Time
	)

	err := s.pool.QueryRow(ctx, `
		SELECT
			digest,
			checkpoint_height,
			checkpoint_block_hash,
			checkpoint_final_orchard_root,
			checkpoint_base_chain_id,
			checkpoint_bridge_contract,
			operator_set_hash,
			ipfs_cid,
			s3_key,
			package_json,
			persisted_at
		FROM checkpoint_packages
		WHERE digest = $1
	`, digest[:]).Scan(
		&digestRaw,
		&height,
		&blockHashRaw,
		&rootRaw,
		&baseChainID,
		&bridgeRaw,
		&opSetHashRaw,
		&ipfsCID,
		&blobKey,
		&payload,
		&persistedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return checkpoint.PackageRecord{}, checkpoint.ErrPackageNotFound
		}
		return checkpoint.PackageRecord{}, fmt.Errorf("checkpoint/postgres: get package: %w", err)
	}

	d, err := toHash(digestRaw)
	if err != nil {
		return checkpoint.PackageRecord{}, err
	}
	blockHash, err := toHash(blockHashRaw)
	if err != nil {
		return checkpoint.PackageRecord{}, err
	}
	root, err := toHash(rootRaw)
	if err != nil {
		return checkpoint.PackageRecord{}, err
	}
	bridge, err := toAddress(bridgeRaw)
	if err != nil {
		return checkpoint.PackageRecord{}, err
	}
	opSetHash, err := toHash(opSetHashRaw)
	if err != nil {
		return checkpoint.PackageRecord{}, err
	}
	if height < 0 || baseChainID < 0 {
		return checkpoint.PackageRecord{}, fmt.Errorf("checkpoint/postgres: negative values in db")
	}

	rec := checkpoint.PackageRecord{
		Digest: d,
		Checkpoint: checkpoint.Checkpoint{
			Height:           uint64(height),
			BlockHash:        blockHash,
			FinalOrchardRoot: root,
			BaseChainID:      uint64(baseChainID),
			BridgeContract:   bridge,
		},
		OperatorSetHash: opSetHash,
		Payload:         append([]byte(nil), payload...),
		PersistedAt:     persistedAt.UTC(),
	}
	if ipfsCID != nil {
		rec.IPFSCID = *ipfsCID
	}
	if blobKey != nil {
		rec.BlobKey = *blobKey
	}
	return rec, nil
}

func nullableString(v string) any {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return v
}

func toHash(raw []byte) (common.Hash, error) {
	if len(raw) != 32 {
		return common.Hash{}, fmt.Errorf("checkpoint/postgres: expected 32 bytes, got %d", len(raw))
	}
	var out common.Hash
	copy(out[:], raw)
	return out, nil
}

func toAddress(raw []byte) (common.Address, error) {
	if len(raw) != 20 {
		return common.Address{}, fmt.Errorf("checkpoint/postgres: expected 20 bytes, got %d", len(raw))
	}
	var out common.Address
	copy(out[:], raw)
	return out, nil
}

var _ checkpoint.PackageStore = (*Store)(nil)
