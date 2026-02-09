package batching

import (
	"encoding/hex"
	"sync"
	"testing"
	"time"
)

func must32Hex(t *testing.T, s string) [32]byte {
	t.Helper()

	s = trim0x(s)
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func trim0x(s string) string {
	if len(s) >= 2 && s[0:2] == "0x" {
		return s[2:]
	}
	return s
}

func seq32(start byte) (out [32]byte) {
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
}

func TestBatcher_FlushesOnMaxItems(t *testing.T) {
	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	b, err := New[int](Config{
		MaxItems: 2,
		MaxAge:   3 * time.Minute,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, ok := b.Add(seq32(0x00), 1); ok {
		t.Fatalf("unexpected flush on first add")
	}
	got, ok := b.Add(seq32(0x20), 2)
	if !ok {
		t.Fatalf("expected flush on maxItems")
	}
	if len(got.Items) != 2 {
		t.Fatalf("got %d items, want 2", len(got.Items))
	}
	if got.Items[0].Val != 1 || got.Items[1].Val != 2 {
		t.Fatalf("unexpected values: %+v", got.Items)
	}
	if !got.StartedAt.Equal(now) {
		t.Fatalf("StartedAt: got %v want %v", got.StartedAt, now)
	}
	if b.Len() != 0 {
		t.Fatalf("expected empty after flush, got len=%d", b.Len())
	}
}

func TestBatcher_FlushesOnMaxAge(t *testing.T) {
	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	b, err := New[int](Config{
		MaxItems: 100,
		MaxAge:   3 * time.Minute,
		Now:      nowFn,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, ok := b.Add(seq32(0x00), 1); ok {
		t.Fatalf("unexpected flush on add")
	}

	now = now.Add(2*time.Minute + 59*time.Second)
	if _, ok := b.FlushDue(); ok {
		t.Fatalf("unexpected flush before maxAge")
	}

	now = now.Add(1 * time.Second)
	got, ok := b.FlushDue()
	if !ok {
		t.Fatalf("expected flush at maxAge")
	}
	if len(got.Items) != 1 {
		t.Fatalf("got %d items, want 1", len(got.Items))
	}
	if got.Items[0].Val != 1 {
		t.Fatalf("unexpected value: %+v", got.Items)
	}
}

func TestWithdrawalBatchIDV1_DeterministicAndMatchesVector(t *testing.T) {
	// Unsorted input should not affect output.
	ids := [][32]byte{
		seq32(0x40),
		seq32(0x00),
		seq32(0x20),
	}

	got := WithdrawalBatchIDV1(ids)
	want := must32Hex(t, "0x9d0777bec6707291ee9247f687821acaa743fe94a3e7dc9401affdba38f69e8a")
	if got != want {
		t.Fatalf("WithdrawalBatchIDV1 mismatch: got %x want %x", got, want)
	}

	// Same items, different order => same id.
	ids2 := [][32]byte{
		seq32(0x20),
		seq32(0x40),
		seq32(0x00),
	}
	got2 := WithdrawalBatchIDV1(ids2)
	if got2 != want {
		t.Fatalf("WithdrawalBatchIDV1 order dependence: got %x want %x", got2, want)
	}
}

func TestBatcher_ConcurrentAddsDoNotDoubleFlush(t *testing.T) {
	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	b, err := New[int](Config{
		MaxItems: 10,
		MaxAge:   1 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const n = 100
	batches := make(chan Batch[int], n)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			id := seq32(byte(i))
			if got, ok := b.Add(id, i); ok {
				batches <- got
			}
		}()
	}
	wg.Wait()

	if got, ok := b.Flush(); ok {
		batches <- got
	}
	close(batches)

	seen := make(map[[32]byte]struct{}, n)
	total := 0
	for batch := range batches {
		for _, it := range batch.Items {
			if _, ok := seen[it.ID]; ok {
				t.Fatalf("duplicate item in flushed batches: %x", it.ID)
			}
			seen[it.ID] = struct{}{}
			total++
		}
	}
	if total != n {
		t.Fatalf("flushed items: got %d want %d", total, n)
	}
}

