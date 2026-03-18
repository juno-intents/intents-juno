package postgres

import (
	"bytes"
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
	if rec.State != checkpoint.PackageStateOpen && rec.State != checkpoint.PackageStateEmitted {
		return fmt.Errorf("%w: invalid state %s", checkpoint.ErrInvalidPackageEnvelope, rec.State)
	}

	persistedAt := rec.PersistedAt
	if persistedAt.IsZero() {
		persistedAt = time.Now().UTC()
	}
	var emittedAt any
	if !rec.EmittedAt.IsZero() {
		emittedAt = rec.EmittedAt.UTC()
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
			pin_state,
			pin_attempts,
			pin_last_error,
			pin_last_attempt_at,
			pin_next_attempt_at,
			pin_claim_owner,
			pin_claim_until,
			s3_key,
			package_json,
			state,
			persisted_at,
			emitted_at,
			updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,now())
		ON CONFLICT (digest) DO UPDATE
		SET
			checkpoint_height = EXCLUDED.checkpoint_height,
			checkpoint_block_hash = EXCLUDED.checkpoint_block_hash,
			checkpoint_final_orchard_root = EXCLUDED.checkpoint_final_orchard_root,
			checkpoint_base_chain_id = EXCLUDED.checkpoint_base_chain_id,
			checkpoint_bridge_contract = EXCLUDED.checkpoint_bridge_contract,
			operator_set_hash = EXCLUDED.operator_set_hash,
			ipfs_cid = EXCLUDED.ipfs_cid,
			pin_state = EXCLUDED.pin_state,
			pin_attempts = EXCLUDED.pin_attempts,
			pin_last_error = EXCLUDED.pin_last_error,
			pin_last_attempt_at = EXCLUDED.pin_last_attempt_at,
			pin_next_attempt_at = EXCLUDED.pin_next_attempt_at,
			pin_claim_owner = EXCLUDED.pin_claim_owner,
			pin_claim_until = EXCLUDED.pin_claim_until,
			s3_key = EXCLUDED.s3_key,
			package_json = EXCLUDED.package_json,
			state = EXCLUDED.state,
			persisted_at = EXCLUDED.persisted_at,
			emitted_at = EXCLUDED.emitted_at,
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
		int16(rec.PinState),
		rec.PinAttempts,
		strings.TrimSpace(rec.PinLastError),
		nullableTime(rec.PinLastAttemptAt),
		nullableTime(rec.PinNextAttemptAt),
		strings.TrimSpace(rec.PinClaimOwner),
		nullableTime(rec.PinClaimUntil),
		nullableString(rec.BlobKey),
		rec.Payload,
		int16(rec.State),
		persistedAt,
		emittedAt,
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
		digestRaw        []byte
		height           int64
		blockHashRaw     []byte
		rootRaw          []byte
		baseChainID      int64
		bridgeRaw        []byte
		opSetHashRaw     []byte
		ipfsCID          *string
		pinState         int16
		pinAttempts      int32
		pinLastError     string
		pinLastAttemptAt *time.Time
		pinNextAttemptAt *time.Time
		pinClaimOwner    string
		pinClaimUntil    *time.Time
		blobKey          *string
		payload          []byte
		state            int16
		persistedAt      time.Time
		emittedAt        *time.Time
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
			pin_state,
			pin_attempts,
			pin_last_error,
			pin_last_attempt_at,
			pin_next_attempt_at,
			pin_claim_owner,
			pin_claim_until,
			s3_key,
			package_json,
			state,
			persisted_at,
			emitted_at
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
		&pinState,
		&pinAttempts,
		&pinLastError,
		&pinLastAttemptAt,
		&pinNextAttemptAt,
		&pinClaimOwner,
		&pinClaimUntil,
		&blobKey,
		&payload,
		&state,
		&persistedAt,
		&emittedAt,
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
		PinState:        checkpoint.PackagePinState(pinState),
		PinAttempts:     int(pinAttempts),
		PinLastError:    strings.TrimSpace(pinLastError),
		PinClaimOwner:   strings.TrimSpace(pinClaimOwner),
		State:           checkpoint.PackageState(state),
		PersistedAt:     persistedAt.UTC(),
	}
	if ipfsCID != nil {
		rec.IPFSCID = *ipfsCID
	}
	if blobKey != nil {
		rec.BlobKey = *blobKey
	}
	if emittedAt != nil {
		rec.EmittedAt = (*emittedAt).UTC()
	}
	if pinLastAttemptAt != nil {
		rec.PinLastAttemptAt = (*pinLastAttemptAt).UTC()
	}
	if pinNextAttemptAt != nil {
		rec.PinNextAttemptAt = (*pinNextAttemptAt).UTC()
	}
	if pinClaimUntil != nil {
		rec.PinClaimUntil = (*pinClaimUntil).UTC()
	}
	return rec, nil
}

func (s *Store) ListByState(ctx context.Context, state checkpoint.PackageState) ([]checkpoint.PackageRecord, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT digest
		FROM checkpoint_packages
		WHERE state = $1
		ORDER BY persisted_at ASC, digest ASC
	`, int16(state))
	if err != nil {
		return nil, fmt.Errorf("checkpoint/postgres: list packages by state: %w", err)
	}
	defer rows.Close()

	var out []checkpoint.PackageRecord
	for rows.Next() {
		var digestRaw []byte
		if err := rows.Scan(&digestRaw); err != nil {
			return nil, fmt.Errorf("checkpoint/postgres: scan package digest: %w", err)
		}
		digest, err := toHash(digestRaw)
		if err != nil {
			return nil, err
		}
		rec, err := s.Get(ctx, digest)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("checkpoint/postgres: list packages by state rows: %w", err)
	}
	return out, nil
}

func (s *Store) ListReadyToPin(ctx context.Context, now time.Time, limit int) ([]checkpoint.PackageRecord, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT digest
		FROM checkpoint_packages
		WHERE pin_state IN ($1, $2)
		  AND (pin_next_attempt_at IS NULL OR pin_next_attempt_at <= $3)
		  AND (
		  	btrim(pin_claim_owner) = ''
		  	OR pin_claim_until IS NULL
		  	OR pin_claim_until <= $3
		  )
		ORDER BY COALESCE(pin_next_attempt_at, persisted_at) ASC, persisted_at ASC, digest ASC
		LIMIT $4
	`, int16(checkpoint.PackagePinStatePending), int16(checkpoint.PackagePinStateFailed), now.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("checkpoint/postgres: list ready to pin: %w", err)
	}
	defer rows.Close()

	out := make([]checkpoint.PackageRecord, 0, limit)
	for rows.Next() {
		var digestRaw []byte
		if err := rows.Scan(&digestRaw); err != nil {
			return nil, fmt.Errorf("checkpoint/postgres: scan pin-ready digest: %w", err)
		}
		digest, err := toHash(digestRaw)
		if err != nil {
			return nil, err
		}
		rec, err := s.Get(ctx, digest)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("checkpoint/postgres: list ready to pin rows: %w", err)
	}
	return out, nil
}

func (s *Store) ClaimReadyToPin(ctx context.Context, owner string, claimTTL time.Duration, now time.Time, limit int) ([]checkpoint.PackageRecord, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if limit <= 0 {
		return nil, nil
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil, fmt.Errorf("%w: pin claim owner is required", checkpoint.ErrInvalidPersistenceConfig)
	}
	if claimTTL <= 0 {
		claimTTL = time.Minute
	}
	claimUntil := now.UTC().Add(claimTTL)

	rows, err := s.pool.Query(ctx, `
		WITH candidates AS (
			SELECT digest
			FROM checkpoint_packages
			WHERE pin_state IN ($1, $2)
			  AND (pin_next_attempt_at IS NULL OR pin_next_attempt_at <= $3)
			  AND (
			  	btrim(pin_claim_owner) = ''
			  	OR pin_claim_until IS NULL
			  	OR pin_claim_until <= $3
			  )
			ORDER BY COALESCE(pin_next_attempt_at, persisted_at) ASC, persisted_at ASC, digest ASC
			LIMIT $4
			FOR UPDATE SKIP LOCKED
		)
		UPDATE checkpoint_packages AS p
		SET
			pin_claim_owner = $5,
			pin_claim_until = $6,
			updated_at = now()
		FROM candidates
		WHERE p.digest = candidates.digest
		RETURNING p.digest
	`, int16(checkpoint.PackagePinStatePending), int16(checkpoint.PackagePinStateFailed), now.UTC(), limit, owner, claimUntil)
	if err != nil {
		return nil, fmt.Errorf("checkpoint/postgres: claim ready to pin: %w", err)
	}
	defer rows.Close()

	out := make([]checkpoint.PackageRecord, 0, limit)
	for rows.Next() {
		var digestRaw []byte
		if err := rows.Scan(&digestRaw); err != nil {
			return nil, fmt.Errorf("checkpoint/postgres: scan pin-claimed digest: %w", err)
		}
		digest, err := toHash(digestRaw)
		if err != nil {
			return nil, err
		}
		rec, err := s.Get(ctx, digest)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("checkpoint/postgres: claim ready to pin rows: %w", err)
	}
	return out, nil
}

func (s *Store) UpdateClaimedPin(ctx context.Context, owner string, now time.Time, rec checkpoint.PackageRecord) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if rec.Digest == (common.Hash{}) || len(rec.Payload) == 0 {
		return fmt.Errorf("%w: missing digest/payload", checkpoint.ErrInvalidPackageEnvelope)
	}
	if rec.State != checkpoint.PackageStateOpen && rec.State != checkpoint.PackageStateEmitted {
		return fmt.Errorf("%w: invalid state %s", checkpoint.ErrInvalidPackageEnvelope, rec.State)
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return fmt.Errorf("%w: pin claim owner is required", checkpoint.ErrInvalidPersistenceConfig)
	}

	persistedAt := rec.PersistedAt
	if persistedAt.IsZero() {
		persistedAt = time.Now().UTC()
	}
	var emittedAt any
	if !rec.EmittedAt.IsZero() {
		emittedAt = rec.EmittedAt.UTC()
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE checkpoint_packages
		SET
			checkpoint_height = $2,
			checkpoint_block_hash = $3,
			checkpoint_final_orchard_root = $4,
			checkpoint_base_chain_id = $5,
			checkpoint_bridge_contract = $6,
			operator_set_hash = $7,
			ipfs_cid = $8,
			pin_state = $9,
			pin_attempts = $10,
			pin_last_error = $11,
			pin_last_attempt_at = $12,
			pin_next_attempt_at = $13,
			pin_claim_owner = '',
			pin_claim_until = NULL,
			s3_key = $14,
			package_json = $15,
			state = $16,
			persisted_at = $17,
			emitted_at = $18,
			updated_at = now()
		WHERE digest = $1
		  AND pin_claim_owner = $19
		  AND pin_claim_until > $20
	`,
		rec.Digest[:],
		int64(rec.Checkpoint.Height),
		rec.Checkpoint.BlockHash[:],
		rec.Checkpoint.FinalOrchardRoot[:],
		int64(rec.Checkpoint.BaseChainID),
		rec.Checkpoint.BridgeContract[:],
		rec.OperatorSetHash[:],
		nullableString(rec.IPFSCID),
		int16(rec.PinState),
		rec.PinAttempts,
		strings.TrimSpace(rec.PinLastError),
		nullableTime(rec.PinLastAttemptAt),
		nullableTime(rec.PinNextAttemptAt),
		nullableString(rec.BlobKey),
		rec.Payload,
		int16(rec.State),
		persistedAt,
		emittedAt,
		owner,
		now.UTC(),
	)
	if err != nil {
		return fmt.Errorf("checkpoint/postgres: update claimed pin: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	if _, err := s.Get(ctx, rec.Digest); err != nil {
		return err
	}
	return checkpoint.ErrPackagePinClaimLost
}

func (s *Store) RecordCommitment(ctx context.Context, commitment checkpoint.SignerCommitment) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if commitment.BaseChainID == 0 {
		return fmt.Errorf("%w: base chain id must be non-zero", checkpoint.ErrInvalidCheckpointCommitment)
	}
	if commitment.BridgeContract == (common.Address{}) {
		return fmt.Errorf("%w: bridge contract must be non-zero", checkpoint.ErrInvalidCheckpointCommitment)
	}
	if commitment.Operator == (common.Address{}) {
		return fmt.Errorf("%w: operator must be non-zero", checkpoint.ErrInvalidCheckpointCommitment)
	}
	if commitment.Digest == (common.Hash{}) {
		return fmt.Errorf("%w: digest must be non-zero", checkpoint.ErrInvalidCheckpointCommitment)
	}

	signedAt := commitment.SignedAt
	if signedAt.IsZero() {
		signedAt = time.Now().UTC()
	}

	tag, err := s.pool.Exec(ctx, `
		INSERT INTO checkpoint_signer_commitments (
			base_chain_id,
			bridge_contract,
			operator,
			checkpoint_height,
			digest,
			signed_at
		) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT DO NOTHING
	`,
		int64(commitment.BaseChainID),
		commitment.BridgeContract[:],
		commitment.Operator[:],
		int64(commitment.Height),
		commitment.Digest[:],
		signedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("checkpoint/postgres: record commitment: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}

	var digestRaw []byte
	if err := s.pool.QueryRow(ctx, `
		SELECT digest
		FROM checkpoint_signer_commitments
		WHERE base_chain_id = $1
		  AND bridge_contract = $2
		  AND operator = $3
		  AND checkpoint_height = $4
	`,
		int64(commitment.BaseChainID),
		commitment.BridgeContract[:],
		commitment.Operator[:],
		int64(commitment.Height),
	).Scan(&digestRaw); err != nil {
		return fmt.Errorf("checkpoint/postgres: load commitment: %w", err)
	}
	if bytes.Equal(digestRaw, commitment.Digest[:]) {
		return nil
	}
	return checkpoint.ErrCheckpointEquivocation
}

func nullableString(v string) any {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return v
}

func nullableTime(v time.Time) any {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
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
var _ checkpoint.SignerCommitmentStore = (*Store)(nil)
