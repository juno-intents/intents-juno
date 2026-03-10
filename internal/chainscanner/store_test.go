package chainscanner

import (
	"context"
	"testing"
)

func TestMemoryStateStore_GetLastHeight_NotFound(t *testing.T) {
	t.Parallel()
	s := NewMemoryStateStore()
	ctx := context.Background()

	height, err := s.GetLastHeight(ctx, "test-service")
	if err != nil {
		t.Fatalf("GetLastHeight: %v", err)
	}
	if height != 0 {
		t.Fatalf("expected 0 for unknown service, got %d", height)
	}
}

func TestMemoryStateStore_SetAndGet(t *testing.T) {
	t.Parallel()
	s := NewMemoryStateStore()
	ctx := context.Background()

	tests := []struct {
		name        string
		serviceName string
		height      int64
	}{
		{name: "first set", serviceName: "svc-a", height: 100},
		{name: "update existing", serviceName: "svc-a", height: 200},
		{name: "different service", serviceName: "svc-b", height: 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.SetLastHeight(ctx, tt.serviceName, tt.height); err != nil {
				t.Fatalf("SetLastHeight(%q, %d): %v", tt.serviceName, tt.height, err)
			}
			got, err := s.GetLastHeight(ctx, tt.serviceName)
			if err != nil {
				t.Fatalf("GetLastHeight(%q): %v", tt.serviceName, err)
			}
			if got != tt.height {
				t.Fatalf("GetLastHeight(%q): got=%d want=%d", tt.serviceName, got, tt.height)
			}
		})
	}
}

func TestMemoryStateStore_EmptyServiceName(t *testing.T) {
	t.Parallel()
	s := NewMemoryStateStore()
	ctx := context.Background()

	_, err := s.GetLastHeight(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty service name")
	}

	err = s.SetLastHeight(ctx, "", 100)
	if err == nil {
		t.Fatal("expected error for empty service name")
	}
}

func TestMemoryStateStore_EnsureSchema(t *testing.T) {
	t.Parallel()
	s := NewMemoryStateStore()
	ctx := context.Background()

	// EnsureSchema is a no-op for memory store; just verify it doesn't error.
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
}

func TestMemoryStateStore_IsolatedServices(t *testing.T) {
	t.Parallel()
	s := NewMemoryStateStore()
	ctx := context.Background()

	if err := s.SetLastHeight(ctx, "svc-1", 111); err != nil {
		t.Fatalf("SetLastHeight: %v", err)
	}
	if err := s.SetLastHeight(ctx, "svc-2", 222); err != nil {
		t.Fatalf("SetLastHeight: %v", err)
	}

	h1, err := s.GetLastHeight(ctx, "svc-1")
	if err != nil {
		t.Fatalf("GetLastHeight: %v", err)
	}
	if h1 != 111 {
		t.Fatalf("svc-1: got=%d want=111", h1)
	}

	h2, err := s.GetLastHeight(ctx, "svc-2")
	if err != nil {
		t.Fatalf("GetLastHeight: %v", err)
	}
	if h2 != 222 {
		t.Fatalf("svc-2: got=%d want=222", h2)
	}
}

func TestMemoryStateStore_BlockRefs(t *testing.T) {
	t.Parallel()

	s := NewMemoryStateStore()
	ctx := context.Background()
	ref1 := BlockRef{Height: 10, Hash: [32]byte{0x10}, ParentHash: [32]byte{0x09}}
	ref2 := BlockRef{Height: 11, Hash: [32]byte{0x11}, ParentHash: [32]byte{0x10}}

	if err := s.StoreBlockRef(ctx, "svc", ref1); err != nil {
		t.Fatalf("StoreBlockRef(10): %v", err)
	}
	if err := s.StoreBlockRef(ctx, "svc", ref2); err != nil {
		t.Fatalf("StoreBlockRef(11): %v", err)
	}

	got, ok, err := s.GetBlockRef(ctx, "svc", 11)
	if err != nil {
		t.Fatalf("GetBlockRef(11): %v", err)
	}
	if !ok || got.Hash != ref2.Hash || got.ParentHash != ref2.ParentHash {
		t.Fatalf("GetBlockRef(11): got=%+v ok=%v", got, ok)
	}

	if err := s.DeleteBlockRefsFromHeight(ctx, "svc", 11); err != nil {
		t.Fatalf("DeleteBlockRefsFromHeight: %v", err)
	}

	if _, ok, err := s.GetBlockRef(ctx, "svc", 11); err != nil {
		t.Fatalf("GetBlockRef(11) after delete: %v", err)
	} else if ok {
		t.Fatal("expected block ref at height 11 to be deleted")
	}
	if got, ok, err := s.GetBlockRef(ctx, "svc", 10); err != nil {
		t.Fatalf("GetBlockRef(10): %v", err)
	} else if !ok || got.Hash != ref1.Hash {
		t.Fatalf("expected block ref at height 10 to remain")
	}
}
