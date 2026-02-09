package batching

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"
)

const DefaultMaxAge = 3 * time.Minute

var ErrInvalidConfig = errors.New("batching: invalid config")

type Config struct {
	MaxItems int
	MaxAge   time.Duration

	// Now allows deterministic, hermetic tests. If nil, time.Now is used.
	Now func() time.Time
}

type Item[T any] struct {
	ID  [32]byte
	Val T
}

type Batch[T any] struct {
	Items     []Item[T]
	StartedAt time.Time
}

type Batcher[T any] struct {
	mu       sync.Mutex
	maxItems int
	maxAge   time.Duration
	now      func() time.Time

	items     []Item[T]
	startedAt time.Time
}

func New[T any](cfg Config) (*Batcher[T], error) {
	if cfg.MaxItems <= 0 {
		return nil, fmt.Errorf("%w: MaxItems must be > 0", ErrInvalidConfig)
	}
	if cfg.MaxAge <= 0 {
		return nil, fmt.Errorf("%w: MaxAge must be > 0", ErrInvalidConfig)
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	return &Batcher[T]{
		maxItems: cfg.MaxItems,
		maxAge:   cfg.MaxAge,
		now:      nowFn,
	}, nil
}

func (b *Batcher[T]) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

// Add adds an item to the in-progress batch and flushes if MaxItems is reached.
func (b *Batcher[T]) Add(id [32]byte, v T) (Batch[T], bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.items) == 0 {
		b.startedAt = b.now()
	}
	b.items = append(b.items, Item[T]{ID: id, Val: v})
	if len(b.items) < b.maxItems {
		return Batch[T]{}, false
	}

	return b.flushLocked()
}

// FlushDue flushes the current batch if its age is >= MaxAge.
func (b *Batcher[T]) FlushDue() (Batch[T], bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.items) == 0 {
		return Batch[T]{}, false
	}
	if b.now().Sub(b.startedAt) < b.maxAge {
		return Batch[T]{}, false
	}
	return b.flushLocked()
}

// Flush flushes the current batch regardless of age.
func (b *Batcher[T]) Flush() (Batch[T], bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.flushLocked()
}

func (b *Batcher[T]) flushLocked() (Batch[T], bool) {
	if len(b.items) == 0 {
		return Batch[T]{}, false
	}
	items := make([]Item[T], len(b.items))
	copy(items, b.items)

	started := b.startedAt

	b.items = nil
	b.startedAt = time.Time{}

	return Batch[T]{
		Items:     items,
		StartedAt: started,
	}, true
}

// WithdrawalBatchIDV1 computes the deterministic batch id for a set of withdrawals.
//
// Spec:
//
//	withdrawalIdsHash = keccak256(concat(withdrawalId_0, ..., withdrawalId_n))
//	batchId = keccak256("WJUNO_WITHDRAW_BATCH_V1" || withdrawalIdsHash)
//
// where withdrawal ids are sorted ascending lexicographically prior to hashing.
func WithdrawalBatchIDV1(withdrawalIDs [][32]byte) [32]byte {
	if len(withdrawalIDs) == 0 {
		return [32]byte{}
	}

	ids := make([][32]byte, len(withdrawalIDs))
	copy(ids, withdrawalIDs)
	slices.SortFunc(ids, func(a, b [32]byte) int {
		return bytes.Compare(a[:], b[:])
	})

	h1 := sha3.NewLegacyKeccak256()
	for i := range ids {
		_, _ = h1.Write(ids[i][:])
	}
	idsHashBytes := h1.Sum(nil)
	var idsHash [32]byte
	copy(idsHash[:], idsHashBytes)

	h2 := sha3.NewLegacyKeccak256()
	_, _ = h2.Write([]byte("WJUNO_WITHDRAW_BATCH_V1"))
	_, _ = h2.Write(idsHash[:])
	outBytes := h2.Sum(nil)
	var out [32]byte
	copy(out[:], outBytes)
	return out
}

