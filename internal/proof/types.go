package proof

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

var (
	ErrInvalidJob        = errors.New("proof: invalid job")
	ErrJobMismatch       = errors.New("proof: job mismatch")
	ErrNotFound          = errors.New("proof: not found")
	ErrInvalidConfig     = errors.New("proof: invalid config")
	ErrInvalidTransition = errors.New("proof: invalid transition")
)

type LifecycleState string

const (
	StatePending        LifecycleState = "pending"
	StateSubmitting     LifecycleState = "submitting"
	StateFulfilled      LifecycleState = "fulfilled"
	StateFailedRetry    LifecycleState = "failed_retryable"
	StateFailedTerminal LifecycleState = "failed_terminal"
)

type JobRequest struct {
	JobID        common.Hash
	Pipeline     string
	ImageID      common.Hash
	Journal      []byte
	PrivateInput []byte
	Deadline     time.Time
	Priority     int
}

func (j JobRequest) Validate() error {
	if (j.JobID == common.Hash{}) {
		return fmt.Errorf("%w: missing job_id", ErrInvalidJob)
	}
	if strings.TrimSpace(j.Pipeline) == "" {
		return fmt.Errorf("%w: missing pipeline", ErrInvalidJob)
	}
	if (j.ImageID == common.Hash{}) {
		return fmt.Errorf("%w: missing image_id", ErrInvalidJob)
	}
	if len(j.Journal) == 0 {
		return fmt.Errorf("%w: empty journal", ErrInvalidJob)
	}
	if j.Deadline.IsZero() {
		return fmt.Errorf("%w: missing deadline", ErrInvalidJob)
	}
	if j.Priority < 0 {
		return fmt.Errorf("%w: priority must be >= 0", ErrInvalidJob)
	}
	return nil
}

func DecodeJobRequest(payload []byte) (JobRequest, error) {
	var raw struct {
		JobID        string `json:"job_id"`
		Pipeline     string `json:"pipeline"`
		ImageID      string `json:"image_id"`
		Journal      string `json:"journal"`
		PrivateInput string `json:"private_input"`
		Deadline     string `json:"deadline"`
		Priority     int    `json:"priority"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return JobRequest{}, fmt.Errorf("%w: decode payload: %v", ErrInvalidJob, err)
	}

	jobID, err := decodeHash32(raw.JobID)
	if err != nil {
		return JobRequest{}, err
	}
	imageID, err := decodeHash32(raw.ImageID)
	if err != nil {
		return JobRequest{}, err
	}
	journal, err := decodeHexBytes(raw.Journal)
	if err != nil {
		return JobRequest{}, err
	}
	privateInput, err := decodeHexBytesAllowEmpty(raw.PrivateInput)
	if err != nil {
		return JobRequest{}, err
	}
	deadline, err := time.Parse(time.RFC3339, strings.TrimSpace(raw.Deadline))
	if err != nil {
		return JobRequest{}, fmt.Errorf("%w: invalid deadline", ErrInvalidJob)
	}

	job := JobRequest{
		JobID:        jobID,
		Pipeline:     strings.TrimSpace(raw.Pipeline),
		ImageID:      imageID,
		Journal:      journal,
		PrivateInput: privateInput,
		Deadline:     deadline.UTC(),
		Priority:     raw.Priority,
	}
	if err := job.Validate(); err != nil {
		return JobRequest{}, err
	}
	return job, nil
}

func decodeHash32(v string) (common.Hash, error) {
	s := strings.TrimSpace(v)
	if !strings.HasPrefix(s, "0x") || len(s) != 66 {
		return common.Hash{}, fmt.Errorf("%w: hash must be 32-byte 0x hex", ErrInvalidJob)
	}
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return common.Hash{}, fmt.Errorf("%w: invalid hash", ErrInvalidJob)
	}
	if len(b) != common.HashLength {
		return common.Hash{}, fmt.Errorf("%w: hash must be 32 bytes", ErrInvalidJob)
	}
	return common.BytesToHash(b), nil
}

func decodeHexBytes(v string) ([]byte, error) {
	s := strings.TrimSpace(strings.TrimPrefix(v, "0x"))
	if s == "" {
		return nil, fmt.Errorf("%w: empty hex bytes", ErrInvalidJob)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hex bytes", ErrInvalidJob)
	}
	return b, nil
}

func decodeHexBytesAllowEmpty(v string) ([]byte, error) {
	s := strings.TrimSpace(strings.TrimPrefix(v, "0x"))
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hex bytes", ErrInvalidJob)
	}
	return b, nil
}

type JobRecord struct {
	Job JobRequest

	RequestID uint64
	State     LifecycleState

	AttemptCount        int
	ProcessingOwner     string
	ProcessingExpiresAt time.Time
	CallbackExpiresAt   time.Time

	SubmissionPath string
	Seal           []byte
	Metadata       map[string]string

	Retryable    bool
	ErrorCode    string
	ErrorMessage string

	CreatedAt time.Time
	UpdatedAt time.Time
}

type Store interface {
	UpsertJob(ctx context.Context, job JobRequest, callbackTTL time.Duration) (bool, error)
	AllocateRequestID(ctx context.Context, chainID uint64) (uint64, error)
	ClaimForSubmission(ctx context.Context, jobID common.Hash, owner string, leaseTTL time.Duration, chainID uint64) (JobRecord, bool, error)
	MarkFulfilled(ctx context.Context, jobID common.Hash, owner string, requestID uint64, seal []byte, metadata map[string]string, submissionPath string) (JobRecord, error)
	MarkFailed(ctx context.Context, jobID common.Hash, owner string, requestID uint64, code, message string, retryable bool) (JobRecord, error)
	GetJob(ctx context.Context, jobID common.Hash) (JobRecord, error)
}

type FulfillmentMessage struct {
	JobID          common.Hash
	RequestID      uint64
	Seal           []byte
	Metadata       map[string]string
	SubmissionPath string
}

type FailureMessage struct {
	JobID     common.Hash
	RequestID uint64
	ErrorCode string
	Retryable bool
	Message   string
}

func EncodeFulfillmentMessage(msg FulfillmentMessage) ([]byte, error) {
	out := struct {
		Version        string            `json:"version"`
		JobID          string            `json:"job_id"`
		RequestID      uint64            `json:"request_id"`
		Seal           string            `json:"seal"`
		Metadata       map[string]string `json:"metadata,omitempty"`
		SubmissionPath string            `json:"submission_path,omitempty"`
	}{
		Version:        "proof.fulfillment.v1",
		JobID:          msg.JobID.Hex(),
		RequestID:      msg.RequestID,
		Seal:           "0x" + hex.EncodeToString(msg.Seal),
		Metadata:       cloneMap(msg.Metadata),
		SubmissionPath: strings.TrimSpace(msg.SubmissionPath),
	}
	return json.Marshal(out)
}

func EncodeFailureMessage(msg FailureMessage) ([]byte, error) {
	out := struct {
		Version   string `json:"version"`
		JobID     string `json:"job_id"`
		RequestID uint64 `json:"request_id,omitempty"`
		ErrorCode string `json:"error_code"`
		Retryable bool   `json:"retryable"`
		Message   string `json:"message,omitempty"`
	}{
		Version:   "proof.failure.v1",
		JobID:     msg.JobID.Hex(),
		RequestID: msg.RequestID,
		ErrorCode: strings.TrimSpace(msg.ErrorCode),
		Retryable: msg.Retryable,
		Message:   strings.TrimSpace(msg.Message),
	}
	return json.Marshal(out)
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
