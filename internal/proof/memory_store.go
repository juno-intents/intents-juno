package proof

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type MemoryStore struct {
	mu sync.Mutex

	nowFn func() time.Time

	records   map[common.Hash]JobRecord
	allocator map[uint64]uint64
}

func NewMemoryStore(nowFn func() time.Time) *MemoryStore {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &MemoryStore{
		nowFn:     nowFn,
		records:   make(map[common.Hash]JobRecord),
		allocator: make(map[uint64]uint64),
	}
}

func (s *MemoryStore) UpsertJob(_ context.Context, job JobRequest, callbackTTL time.Duration) (bool, error) {
	if s == nil {
		return false, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if callbackTTL <= 0 {
		return false, fmt.Errorf("%w: callback ttl must be > 0", ErrInvalidConfig)
	}
	if err := job.Validate(); err != nil {
		return false, err
	}

	now := s.nowFn().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.records[job.JobID]
	if ok {
		if !jobEqual(existing.Job, job) {
			return false, ErrJobMismatch
		}
		return false, nil
	}

	s.records[job.JobID] = JobRecord{
		Job:               cloneJob(job),
		State:             StatePending,
		CallbackExpiresAt: now.Add(callbackTTL),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	return true, nil
}

func (s *MemoryStore) AllocateRequestID(_ context.Context, chainID uint64) (uint64, error) {
	if s == nil {
		return 0, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if chainID == 0 {
		return 0, fmt.Errorf("%w: chain id must be > 0", ErrInvalidConfig)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.allocator[chainID] + 1
	s.allocator[chainID] = next
	return next, nil
}

func (s *MemoryStore) ClaimForSubmission(_ context.Context, jobID common.Hash, owner string, leaseTTL time.Duration, chainID uint64) (JobRecord, bool, error) {
	if s == nil {
		return JobRecord{}, false, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if owner == "" || leaseTTL <= 0 || chainID == 0 {
		return JobRecord{}, false, fmt.Errorf("%w: owner/ttl/chain invalid", ErrInvalidConfig)
	}

	now := s.nowFn().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[jobID]
	if !ok {
		return JobRecord{}, false, ErrNotFound
	}
	if rec.State == StateFulfilled || rec.State == StateFailedTerminal {
		return cloneRecord(rec), false, nil
	}
	if rec.ProcessingOwner != "" && rec.ProcessingOwner != owner && rec.ProcessingExpiresAt.After(now) {
		return cloneRecord(rec), false, nil
	}
	if rec.RequestID == 0 {
		next := s.allocator[chainID] + 1
		s.allocator[chainID] = next
		rec.RequestID = next
	}
	rec.AttemptCount++
	rec.State = StateSubmitting
	rec.ProcessingOwner = owner
	rec.ProcessingExpiresAt = now.Add(leaseTTL)
	rec.UpdatedAt = now

	s.records[jobID] = rec
	return cloneRecord(rec), true, nil
}

func (s *MemoryStore) MarkFulfilled(_ context.Context, jobID common.Hash, owner string, requestID uint64, seal []byte, metadata map[string]string, submissionPath string) (JobRecord, error) {
	if s == nil {
		return JobRecord{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	now := s.nowFn().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[jobID]
	if !ok {
		return JobRecord{}, ErrNotFound
	}
	if rec.RequestID != 0 && requestID != 0 && rec.RequestID != requestID {
		return JobRecord{}, ErrInvalidTransition
	}
	if rec.ProcessingOwner != "" && owner != "" && rec.ProcessingOwner != owner {
		return JobRecord{}, ErrInvalidTransition
	}

	if requestID != 0 {
		rec.RequestID = requestID
	}
	rec.State = StateFulfilled
	rec.Retryable = false
	rec.ErrorCode = ""
	rec.ErrorMessage = ""
	rec.Seal = append([]byte(nil), seal...)
	rec.Metadata = cloneMetadata(metadata)
	rec.SubmissionPath = submissionPath
	rec.ProcessingOwner = ""
	rec.ProcessingExpiresAt = time.Time{}
	rec.UpdatedAt = now

	s.records[jobID] = rec
	return cloneRecord(rec), nil
}

func (s *MemoryStore) MarkFailed(_ context.Context, jobID common.Hash, owner string, requestID uint64, code, message string, retryable bool) (JobRecord, error) {
	if s == nil {
		return JobRecord{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	now := s.nowFn().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[jobID]
	if !ok {
		return JobRecord{}, ErrNotFound
	}
	if rec.RequestID != 0 && requestID != 0 && rec.RequestID != requestID {
		return JobRecord{}, ErrInvalidTransition
	}
	if rec.ProcessingOwner != "" && owner != "" && rec.ProcessingOwner != owner {
		return JobRecord{}, ErrInvalidTransition
	}
	if requestID != 0 {
		rec.RequestID = requestID
	}
	if retryable {
		rec.State = StateFailedRetry
	} else {
		rec.State = StateFailedTerminal
	}
	rec.Retryable = retryable
	rec.ErrorCode = code
	rec.ErrorMessage = message
	rec.Seal = nil
	rec.SubmissionPath = ""
	rec.ProcessingOwner = ""
	rec.ProcessingExpiresAt = time.Time{}
	rec.UpdatedAt = now

	s.records[jobID] = rec
	return cloneRecord(rec), nil
}

func (s *MemoryStore) GetJob(_ context.Context, jobID common.Hash) (JobRecord, error) {
	if s == nil {
		return JobRecord{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[jobID]
	if !ok {
		return JobRecord{}, ErrNotFound
	}
	return cloneRecord(rec), nil
}

func cloneJob(job JobRequest) JobRequest {
	job.Pipeline = stringsTrim(job.Pipeline)
	job.Journal = append([]byte(nil), job.Journal...)
	job.PrivateInput = append([]byte(nil), job.PrivateInput...)
	return job
}

func stringsTrim(v string) string {
	return strings.TrimSpace(v)
}

func jobEqual(a, b JobRequest) bool {
	return a.JobID == b.JobID &&
		stringsTrim(a.Pipeline) == stringsTrim(b.Pipeline) &&
		a.ImageID == b.ImageID &&
		bytes.Equal(a.Journal, b.Journal) &&
		bytes.Equal(a.PrivateInput, b.PrivateInput) &&
		a.Deadline.UTC().Equal(b.Deadline.UTC()) &&
		a.Priority == b.Priority
}

func cloneRecord(r JobRecord) JobRecord {
	out := r
	out.Job = cloneJob(r.Job)
	out.Seal = append([]byte(nil), r.Seal...)
	out.Metadata = cloneMetadata(r.Metadata)
	return out
}

func cloneMetadata(v map[string]string) map[string]string {
	if len(v) == 0 {
		return nil
	}
	out := make(map[string]string, len(v))
	maps.Copy(out, v)
	return out
}
