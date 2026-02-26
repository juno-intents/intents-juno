package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/proof"
)

var ErrInvalidConfig = errors.New("proof/postgres: invalid config")

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
		return fmt.Errorf("proof/postgres: ensure schema: %w", err)
	}
	return nil
}

func (s *Store) UpsertJob(ctx context.Context, job proof.JobRequest, callbackTTL time.Duration) (bool, error) {
	if s == nil || s.pool == nil {
		return false, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if callbackTTL <= 0 {
		return false, fmt.Errorf("%w: callback ttl must be > 0", proof.ErrInvalidConfig)
	}
	if err := job.Validate(); err != nil {
		return false, err
	}

	tag, err := s.pool.Exec(ctx, `
		INSERT INTO proof_jobs (
			job_id,
			pipeline,
			image_id,
			journal,
			private_input,
			deadline,
			priority,
			callback_expires_at,
			state,
			created_at,
			updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7, now() + ($8::bigint * interval '1 millisecond'), $9, now(), now())
		ON CONFLICT (job_id) DO NOTHING
	`, hashToBytes(job.JobID), strings.TrimSpace(job.Pipeline), hashToBytes(job.ImageID), job.Journal, job.PrivateInput, job.Deadline.UTC(), job.Priority, callbackTTL.Milliseconds(), stateToDB(proof.StatePending))
	if err != nil {
		return false, fmt.Errorf("proof/postgres: insert job: %w", err)
	}
	if tag.RowsAffected() == 1 {
		_ = s.appendEvent(ctx, job.JobID, "job_created", map[string]any{
			"pipeline": job.Pipeline,
		})
		return true, nil
	}

	rec, err := s.GetJob(ctx, job.JobID)
	if err != nil {
		return false, err
	}
	if !jobsEqual(rec.Job, job) {
		return false, proof.ErrJobMismatch
	}
	return false, nil
}

func (s *Store) AllocateRequestID(ctx context.Context, chainID uint64) (uint64, error) {
	if s == nil || s.pool == nil {
		return 0, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if chainID == 0 {
		return 0, fmt.Errorf("%w: chain id must be > 0", proof.ErrInvalidConfig)
	}

	var requestID uint64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO proof_request_ids (chain_id, next_request_id, updated_at)
		VALUES ($1, 2, now())
		ON CONFLICT (chain_id) DO UPDATE
		SET next_request_id = proof_request_ids.next_request_id + 1,
			updated_at = now()
		RETURNING next_request_id - 1
	`, int64(chainID)).Scan(&requestID)
	if err != nil {
		return 0, fmt.Errorf("proof/postgres: allocate request id: %w", err)
	}
	return requestID, nil
}

func (s *Store) ClaimForSubmission(ctx context.Context, jobID common.Hash, owner string, leaseTTL time.Duration, chainID uint64) (proof.JobRecord, bool, error) {
	if s == nil || s.pool == nil {
		return proof.JobRecord{}, false, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	owner = strings.TrimSpace(owner)
	if owner == "" || leaseTTL <= 0 || chainID == 0 {
		return proof.JobRecord{}, false, proof.ErrInvalidConfig
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return proof.JobRecord{}, false, fmt.Errorf("proof/postgres: begin claim tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rec, err := getJobForUpdate(ctx, tx, jobID)
	if err != nil {
		return proof.JobRecord{}, false, err
	}

	now := time.Now().UTC()
	if rec.State == proof.StateFulfilled || rec.State == proof.StateFailedTerminal {
		if err := tx.Commit(ctx); err != nil {
			return proof.JobRecord{}, false, fmt.Errorf("proof/postgres: commit claim read-only: %w", err)
		}
		return rec, false, nil
	}
	if rec.ProcessingOwner != "" && rec.ProcessingOwner != owner && rec.ProcessingExpiresAt.After(now) {
		if err := tx.Commit(ctx); err != nil {
			return proof.JobRecord{}, false, fmt.Errorf("proof/postgres: commit claim read-only: %w", err)
		}
		return rec, false, nil
	}

	requestID := rec.RequestID
	if requestID == 0 {
		requestID, err = allocateRequestIDTx(ctx, tx, chainID)
		if err != nil {
			return proof.JobRecord{}, false, err
		}
	}

	var metadataRaw []byte
	var (
		imageRaw        []byte
		stateRaw        int16
		requestRaw      int64
		ownerRaw        *string
		expiresRaw      *time.Time
		submissionRaw   *string
		errorCodeRaw    *string
		errorMessageRaw *string
	)
	err = tx.QueryRow(ctx, `
		UPDATE proof_jobs
		SET request_id = $2,
			state = $3,
			attempt_count = attempt_count + 1,
			processing_owner = $4,
			processing_expires_at = now() + ($5::bigint * interval '1 millisecond'),
			updated_at = now()
		WHERE job_id = $1
		RETURNING
			pipeline,
			image_id,
			journal,
			private_input,
			deadline,
			priority,
			callback_expires_at,
			request_id,
			state,
			attempt_count,
			processing_owner,
			processing_expires_at,
			submission_path,
			seal,
			metadata,
			retryable,
			error_code,
			error_message,
			created_at,
			updated_at
	`, hashToBytes(jobID), requestID, stateToDB(proof.StateSubmitting), owner, leaseTTL.Milliseconds()).Scan(
		&rec.Job.Pipeline,
		&imageRaw,
		&rec.Job.Journal,
		&rec.Job.PrivateInput,
		&rec.Job.Deadline,
		&rec.Job.Priority,
		&rec.CallbackExpiresAt,
		&requestRaw,
		&stateRaw,
		&rec.AttemptCount,
		&ownerRaw,
		&expiresRaw,
		&submissionRaw,
		&rec.Seal,
		&metadataRaw,
		&rec.Retryable,
		&errorCodeRaw,
		&errorMessageRaw,
		&rec.CreatedAt,
		&rec.UpdatedAt,
	)
	if err != nil {
		return proof.JobRecord{}, false, fmt.Errorf("proof/postgres: claim update: %w", err)
	}
	rec.Job.JobID = jobID
	rec.RequestID = uint64(requestRaw)
	rec.Job.ImageID = common.BytesToHash(imageRaw)
	rec.ProcessingOwner = stringOrEmpty(ownerRaw)
	rec.ProcessingExpiresAt = timeOrZero(expiresRaw)
	rec.SubmissionPath = stringOrEmpty(submissionRaw)
	rec.ErrorCode = stringOrEmpty(errorCodeRaw)
	rec.ErrorMessage = stringOrEmpty(errorMessageRaw)
	state, err := stateFromDB(stateRaw)
	if err != nil {
		return proof.JobRecord{}, false, err
	}
	rec.State = state
	if err := decodeMetadata(metadataRaw, &rec.Metadata); err != nil {
		return proof.JobRecord{}, false, err
	}

	if err := appendEventTx(ctx, tx, jobID, "job_claimed", map[string]any{
		"request_id": rec.RequestID,
		"owner":      owner,
	}); err != nil {
		return proof.JobRecord{}, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return proof.JobRecord{}, false, fmt.Errorf("proof/postgres: commit claim tx: %w", err)
	}
	return rec, true, nil
}

func (s *Store) MarkFulfilled(ctx context.Context, jobID common.Hash, owner string, requestID uint64, seal []byte, metadata map[string]string, submissionPath string) (proof.JobRecord, error) {
	if s == nil || s.pool == nil {
		return proof.JobRecord{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if requestID == 0 {
		return proof.JobRecord{}, proof.ErrInvalidConfig
	}
	payload, err := json.Marshal(metadata)
	if err != nil {
		return proof.JobRecord{}, fmt.Errorf("proof/postgres: marshal metadata: %w", err)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return proof.JobRecord{}, fmt.Errorf("proof/postgres: begin fulfill tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rec, err := updateTerminalTx(ctx, tx, terminalUpdate{
		jobID:          jobID,
		owner:          owner,
		requestID:      requestID,
		state:          proof.StateFulfilled,
		retryable:      false,
		errorCode:      "",
		errorMessage:   "",
		submissionPath: strings.TrimSpace(submissionPath),
		seal:           seal,
		metadataJSON:   payload,
	})
	if err != nil {
		return proof.JobRecord{}, err
	}
	if err := appendEventTx(ctx, tx, jobID, "job_fulfilled", map[string]any{
		"request_id":      requestID,
		"submission_path": rec.SubmissionPath,
	}); err != nil {
		return proof.JobRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return proof.JobRecord{}, fmt.Errorf("proof/postgres: commit fulfill tx: %w", err)
	}
	return rec, nil
}

func (s *Store) MarkFailed(ctx context.Context, jobID common.Hash, owner string, requestID uint64, code, message string, retryable bool) (proof.JobRecord, error) {
	if s == nil || s.pool == nil {
		return proof.JobRecord{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	state := proof.StateFailedTerminal
	if retryable {
		state = proof.StateFailedRetry
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return proof.JobRecord{}, fmt.Errorf("proof/postgres: begin fail tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rec, err := updateTerminalTx(ctx, tx, terminalUpdate{
		jobID:          jobID,
		owner:          owner,
		requestID:      requestID,
		state:          state,
		retryable:      retryable,
		errorCode:      strings.TrimSpace(code),
		errorMessage:   strings.TrimSpace(message),
		submissionPath: "",
		seal:           nil,
		metadataJSON:   []byte(`{}`),
	})
	if err != nil {
		return proof.JobRecord{}, err
	}
	if err := appendEventTx(ctx, tx, jobID, "job_failed", map[string]any{
		"request_id": rec.RequestID,
		"retryable":  retryable,
		"error_code": rec.ErrorCode,
	}); err != nil {
		return proof.JobRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return proof.JobRecord{}, fmt.Errorf("proof/postgres: commit fail tx: %w", err)
	}
	return rec, nil
}

func (s *Store) GetJob(ctx context.Context, jobID common.Hash) (proof.JobRecord, error) {
	if s == nil || s.pool == nil {
		return proof.JobRecord{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	return getJob(ctx, s.pool, jobID)
}

type terminalUpdate struct {
	jobID          common.Hash
	owner          string
	requestID      uint64
	state          proof.LifecycleState
	retryable      bool
	errorCode      string
	errorMessage   string
	submissionPath string
	seal           []byte
	metadataJSON   []byte
}

func updateTerminalTx(ctx context.Context, tx pgx.Tx, in terminalUpdate) (proof.JobRecord, error) {
	var (
		rec             proof.JobRecord
		metadataRaw     []byte
		imageRaw        []byte
		stateRaw        int16
		requestRaw      *int64
		ownerRaw        *string
		expiresRaw      *time.Time
		submissionRaw   *string
		errorCodeRaw    *string
		errorMessageRaw *string
	)

	err := tx.QueryRow(ctx, `
		UPDATE proof_jobs
		SET request_id = COALESCE(request_id, $2),
			state = $3,
			retryable = $4,
			error_code = NULLIF($5, ''),
			error_message = NULLIF($6, ''),
			submission_path = NULLIF($7, ''),
			seal = $8,
			metadata = $9::jsonb,
			processing_owner = NULL,
			processing_expires_at = NULL,
			updated_at = now()
		WHERE job_id = $1
			AND ($10 = '' OR processing_owner IS NULL OR processing_owner = $10)
		RETURNING
			pipeline,
			image_id,
			journal,
			private_input,
			deadline,
			priority,
			callback_expires_at,
			request_id,
			state,
			attempt_count,
			processing_owner,
			processing_expires_at,
			submission_path,
			seal,
			metadata,
			retryable,
			error_code,
			error_message,
			created_at,
			updated_at
	`, hashToBytes(in.jobID), in.requestID, stateToDB(in.state), in.retryable, in.errorCode, in.errorMessage, in.submissionPath, in.seal, in.metadataJSON, strings.TrimSpace(in.owner)).Scan(
		&rec.Job.Pipeline,
		&imageRaw,
		&rec.Job.Journal,
		&rec.Job.PrivateInput,
		&rec.Job.Deadline,
		&rec.Job.Priority,
		&rec.CallbackExpiresAt,
		&requestRaw,
		&stateRaw,
		&rec.AttemptCount,
		&ownerRaw,
		&expiresRaw,
		&submissionRaw,
		&rec.Seal,
		&metadataRaw,
		&rec.Retryable,
		&errorCodeRaw,
		&errorMessageRaw,
		&rec.CreatedAt,
		&rec.UpdatedAt,
	)
	if err == nil {
		rec.Job.JobID = in.jobID
		if requestRaw != nil {
			rec.RequestID = uint64(*requestRaw)
		}
		rec.Job.ImageID = common.BytesToHash(imageRaw)
		rec.ProcessingOwner = stringOrEmpty(ownerRaw)
		rec.ProcessingExpiresAt = timeOrZero(expiresRaw)
		rec.SubmissionPath = stringOrEmpty(submissionRaw)
		rec.ErrorCode = stringOrEmpty(errorCodeRaw)
		rec.ErrorMessage = stringOrEmpty(errorMessageRaw)
		state, serr := stateFromDB(stateRaw)
		if serr != nil {
			return proof.JobRecord{}, serr
		}
		rec.State = state
		if err := decodeMetadata(metadataRaw, &rec.Metadata); err != nil {
			return proof.JobRecord{}, err
		}
		return rec, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return proof.JobRecord{}, fmt.Errorf("proof/postgres: update terminal state: %w", err)
	}

	rec, gerr := getJobForUpdate(ctx, tx, in.jobID)
	if gerr != nil {
		return proof.JobRecord{}, gerr
	}
	if rec.State == in.state {
		return rec, nil
	}
	return proof.JobRecord{}, proof.ErrInvalidTransition
}

func getJob(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, jobID common.Hash) (proof.JobRecord, error) {
	var (
		rec             proof.JobRecord
		metadataRaw     []byte
		imageRaw        []byte
		stateRaw        int16
		requestRaw      *int64
		ownerRaw        *string
		expiresRaw      *time.Time
		submissionRaw   *string
		errorCodeRaw    *string
		errorMessageRaw *string
	)
	err := q.QueryRow(ctx, `
		SELECT
			pipeline,
			image_id,
			journal,
			private_input,
			deadline,
			priority,
			callback_expires_at,
			request_id,
			state,
			attempt_count,
			processing_owner,
			processing_expires_at,
			submission_path,
			seal,
			metadata,
			retryable,
			error_code,
			error_message,
			created_at,
			updated_at
		FROM proof_jobs
		WHERE job_id = $1
	`, hashToBytes(jobID)).Scan(
		&rec.Job.Pipeline,
		&imageRaw,
		&rec.Job.Journal,
		&rec.Job.PrivateInput,
		&rec.Job.Deadline,
		&rec.Job.Priority,
		&rec.CallbackExpiresAt,
		&requestRaw,
		&stateRaw,
		&rec.AttemptCount,
		&ownerRaw,
		&expiresRaw,
		&submissionRaw,
		&rec.Seal,
		&metadataRaw,
		&rec.Retryable,
		&errorCodeRaw,
		&errorMessageRaw,
		&rec.CreatedAt,
		&rec.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return proof.JobRecord{}, proof.ErrNotFound
		}
		return proof.JobRecord{}, fmt.Errorf("proof/postgres: get job: %w", err)
	}
	rec.Job.JobID = jobID
	if requestRaw != nil {
		rec.RequestID = uint64(*requestRaw)
	}
	rec.Job.ImageID = common.BytesToHash(imageRaw)
	rec.ProcessingOwner = stringOrEmpty(ownerRaw)
	rec.ProcessingExpiresAt = timeOrZero(expiresRaw)
	rec.SubmissionPath = stringOrEmpty(submissionRaw)
	rec.ErrorCode = stringOrEmpty(errorCodeRaw)
	rec.ErrorMessage = stringOrEmpty(errorMessageRaw)
	state, err := stateFromDB(stateRaw)
	if err != nil {
		return proof.JobRecord{}, err
	}
	rec.State = state
	if err := decodeMetadata(metadataRaw, &rec.Metadata); err != nil {
		return proof.JobRecord{}, err
	}
	return rec, nil
}

func getJobForUpdate(ctx context.Context, tx pgx.Tx, jobID common.Hash) (proof.JobRecord, error) {
	var (
		rec             proof.JobRecord
		metadataRaw     []byte
		imageRaw        []byte
		stateRaw        int16
		requestRaw      *int64
		ownerRaw        *string
		expiresRaw      *time.Time
		submissionRaw   *string
		errorCodeRaw    *string
		errorMessageRaw *string
	)
	err := tx.QueryRow(ctx, `
		SELECT
			pipeline,
			image_id,
			journal,
			private_input,
			deadline,
			priority,
			callback_expires_at,
			request_id,
			state,
			attempt_count,
			processing_owner,
			processing_expires_at,
			submission_path,
			seal,
			metadata,
			retryable,
			error_code,
			error_message,
			created_at,
			updated_at
		FROM proof_jobs
		WHERE job_id = $1
		FOR UPDATE
	`, hashToBytes(jobID)).Scan(
		&rec.Job.Pipeline,
		&imageRaw,
		&rec.Job.Journal,
		&rec.Job.PrivateInput,
		&rec.Job.Deadline,
		&rec.Job.Priority,
		&rec.CallbackExpiresAt,
		&requestRaw,
		&stateRaw,
		&rec.AttemptCount,
		&ownerRaw,
		&expiresRaw,
		&submissionRaw,
		&rec.Seal,
		&metadataRaw,
		&rec.Retryable,
		&errorCodeRaw,
		&errorMessageRaw,
		&rec.CreatedAt,
		&rec.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return proof.JobRecord{}, proof.ErrNotFound
		}
		return proof.JobRecord{}, fmt.Errorf("proof/postgres: get job for update: %w", err)
	}
	rec.Job.JobID = jobID
	if requestRaw != nil {
		rec.RequestID = uint64(*requestRaw)
	}
	rec.Job.ImageID = common.BytesToHash(imageRaw)
	rec.ProcessingOwner = stringOrEmpty(ownerRaw)
	rec.ProcessingExpiresAt = timeOrZero(expiresRaw)
	rec.SubmissionPath = stringOrEmpty(submissionRaw)
	rec.ErrorCode = stringOrEmpty(errorCodeRaw)
	rec.ErrorMessage = stringOrEmpty(errorMessageRaw)
	state, err := stateFromDB(stateRaw)
	if err != nil {
		return proof.JobRecord{}, err
	}
	rec.State = state
	if err := decodeMetadata(metadataRaw, &rec.Metadata); err != nil {
		return proof.JobRecord{}, err
	}
	return rec, nil
}

func allocateRequestIDTx(ctx context.Context, tx pgx.Tx, chainID uint64) (uint64, error) {
	var requestID uint64
	err := tx.QueryRow(ctx, `
		INSERT INTO proof_request_ids (chain_id, next_request_id, updated_at)
		VALUES ($1, 2, now())
		ON CONFLICT (chain_id) DO UPDATE
		SET next_request_id = proof_request_ids.next_request_id + 1,
			updated_at = now()
		RETURNING next_request_id - 1
	`, int64(chainID)).Scan(&requestID)
	if err != nil {
		return 0, fmt.Errorf("proof/postgres: allocate request id tx: %w", err)
	}
	return requestID, nil
}

func (s *Store) appendEvent(ctx context.Context, jobID common.Hash, eventType string, payload map[string]any) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := appendEventTx(ctx, tx, jobID, eventType, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func appendEventTx(ctx context.Context, tx pgx.Tx, jobID common.Hash, eventType string, payload map[string]any) error {
	eventType = strings.TrimSpace(eventType)
	if eventType == "" {
		return nil
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("proof/postgres: marshal event payload: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO proof_events (job_id, event_type, payload, created_at)
		VALUES ($1,$2,$3::jsonb, now())
	`, hashToBytes(jobID), eventType, b); err != nil {
		return fmt.Errorf("proof/postgres: insert event: %w", err)
	}
	return nil
}

func stateToDB(state proof.LifecycleState) int16 {
	switch state {
	case proof.StatePending:
		return 1
	case proof.StateSubmitting:
		return 2
	case proof.StateFulfilled:
		return 3
	case proof.StateFailedRetry:
		return 4
	case proof.StateFailedTerminal:
		return 5
	default:
		return 0
	}
}

func stateFromDB(v int16) (proof.LifecycleState, error) {
	switch v {
	case 1:
		return proof.StatePending, nil
	case 2:
		return proof.StateSubmitting, nil
	case 3:
		return proof.StateFulfilled, nil
	case 4:
		return proof.StateFailedRetry, nil
	case 5:
		return proof.StateFailedTerminal, nil
	default:
		return "", fmt.Errorf("proof/postgres: unknown state %d", v)
	}
}

func decodeMetadata(raw []byte, out *map[string]string) error {
	if len(raw) == 0 {
		*out = nil
		return nil
	}
	var parsed map[string]string
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("proof/postgres: decode metadata: %w", err)
	}
	*out = parsed
	return nil
}

func hashToBytes(v common.Hash) []byte {
	return v[:]
}

func stringOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func timeOrZero(v *time.Time) time.Time {
	if v == nil {
		return time.Time{}
	}
	return *v
}

func jobsEqual(a, b proof.JobRequest) bool {
	return a.JobID == b.JobID &&
		strings.TrimSpace(a.Pipeline) == strings.TrimSpace(b.Pipeline) &&
		a.ImageID == b.ImageID &&
		bytes.Equal(a.Journal, b.Journal) &&
		bytes.Equal(a.PrivateInput, b.PrivateInput)
}
