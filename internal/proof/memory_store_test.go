package proof

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func TestMemoryStore_DedupeOnRepeatedJobID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 11, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })

	job := JobRequest{
		JobID:        common.HexToHash("0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98"),
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01, 0x02},
		PrivateInput: []byte{0x03, 0x04},
		Deadline:     now.Add(5 * time.Minute),
		Priority:     1,
	}

	created, err := store.UpsertJob(context.Background(), job, 72*time.Hour)
	if err != nil {
		t.Fatalf("UpsertJob first: %v", err)
	}
	if !created {
		t.Fatalf("expected first insert to be created")
	}

	created, err = store.UpsertJob(context.Background(), job, 72*time.Hour)
	if err != nil {
		t.Fatalf("UpsertJob second: %v", err)
	}
	if created {
		t.Fatalf("expected repeated job_id to dedupe")
	}

	mismatch := job
	mismatch.Pipeline = "withdraw"
	_, err = store.UpsertJob(context.Background(), mismatch, 72*time.Hour)
	if !errors.Is(err, ErrJobMismatch) {
		t.Fatalf("expected ErrJobMismatch, got %v", err)
	}
}

func TestMemoryStore_RequestIDAllocatorConcurrent(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(time.Now)
	const workers = 100

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		got  = make([]uint64, 0, workers)
		errs = make([]error, 0)
	)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := store.AllocateRequestID(context.Background(), 8453)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			got = append(got, id)
		}()
	}
	wg.Wait()

	if len(errs) != 0 {
		t.Fatalf("unexpected allocator errors: %v", errs)
	}
	if len(got) != workers {
		t.Fatalf("ids: got %d want %d", len(got), workers)
	}

	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	for i := 0; i < workers; i++ {
		want := uint64(i + 1)
		if got[i] != want {
			t.Fatalf("ids[%d]: got %d want %d", i, got[i], want)
		}
	}
}
