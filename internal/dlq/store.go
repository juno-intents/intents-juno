package dlq

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidConfig = errors.New("dlq: invalid config")
	ErrNotFound      = errors.New("dlq: not found")
	ErrInvalidTable  = errors.New("dlq: invalid table name")
)

// Store is the interface for dead-letter queue persistence.
type Store interface {
	EnsureSchema(ctx context.Context) error

	InsertProofDLQ(ctx context.Context, rec ProofDLQRecord) error
	InsertDepositBatchDLQ(ctx context.Context, rec DepositBatchDLQRecord) error
	InsertWithdrawalBatchDLQ(ctx context.Context, rec WithdrawalBatchDLQRecord) error

	ListProofDLQ(ctx context.Context, filter DLQFilter) ([]ProofDLQRecord, error)
	ListDepositBatchDLQ(ctx context.Context, filter DLQFilter) ([]DepositBatchDLQRecord, error)
	ListWithdrawalBatchDLQ(ctx context.Context, filter DLQFilter) ([]WithdrawalBatchDLQRecord, error)

	CountUnacknowledged(ctx context.Context) (DLQCounts, error)

	Acknowledge(ctx context.Context, table string, id []byte) error
}

// ProofDLQRecord represents a failed proof job in the dead-letter queue.
type ProofDLQRecord struct {
	JobID        [32]byte
	Pipeline     string
	ImageID      [32]byte
	State        int16
	ErrorCode    string
	ErrorMessage string
	AttemptCount int
	JobPayload   []byte
	CreatedAt    time.Time
	Acknowledged bool
	AckAt        *time.Time
}

// DepositBatchDLQRecord represents a failed deposit batch in the dead-letter queue.
type DepositBatchDLQRecord struct {
	BatchID      [32]byte
	DepositIDs   [][32]byte
	ItemsCount   int
	State        int16
	FailureStage string
	ErrorCode    string
	ErrorMessage string
	AttemptCount int
	CreatedAt    time.Time
	Acknowledged bool
	AckAt        *time.Time
}

// WithdrawalBatchDLQRecord represents a failed withdrawal batch in the dead-letter queue.
type WithdrawalBatchDLQRecord struct {
	BatchID             [32]byte
	WithdrawalIDs       [][32]byte
	ItemsCount          int
	State               int16
	FailureStage        string
	ErrorCode           string
	ErrorMessage        string
	RebroadcastAttempts int
	JunoTxID            string
	CreatedAt           time.Time
	Acknowledged        bool
	AckAt               *time.Time
}

// DLQFilter specifies optional filters for listing DLQ records.
type DLQFilter struct {
	ErrorCode    string     // optional filter
	FailureStage string    // optional filter
	Acknowledged *bool      // optional filter
	Since        time.Time  // optional filter
	Limit        int        // default 100
	Offset       int
}

// DLQCounts holds the count of unacknowledged records per DLQ table.
type DLQCounts struct {
	Proofs            int
	DepositBatches    int
	WithdrawalBatches int
}

// ValidDLQTables lists the allowed table names for Acknowledge.
var ValidDLQTables = map[string]bool{
	"proof_dlq":            true,
	"deposit_batch_dlq":    true,
	"withdrawal_batch_dlq": true,
}
