package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/leases"
)

func TestLoadDigestSigner_LocalEnv(t *testing.T) {
	t.Setenv("TEST_CHECKPOINT_SIGNER_PRIVATE_KEY", "4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")

	signer, operator, err := loadDigestSigner(context.Background(), "local-env", "", "TEST_CHECKPOINT_SIGNER_PRIVATE_KEY")
	if err != nil {
		t.Fatalf("loadDigestSigner: %v", err)
	}
	if signer == nil {
		t.Fatalf("expected signer")
	}
	want := common.HexToAddress("0xeD99D54580044F325C6e9E12236fa90A165257ff")
	if operator != want {
		t.Fatalf("operator mismatch: got %s want %s", operator, want)
	}
}

func TestLoadDigestSigner_AWSKMSRequiresOperatorAddress(t *testing.T) {
	_, _, err := loadDigestSigner(context.Background(), "aws-kms", "arn:aws:kms:us-east-1:123:key/test", "IGNORED")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "OPERATOR_ADDRESS") {
		t.Fatalf("expected OPERATOR_ADDRESS error, got %v", err)
	}
}

func TestLoadDigestSigner_RejectsUnknownDriver(t *testing.T) {
	_, _, err := loadDigestSigner(context.Background(), "bad-driver", "", "IGNORED")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported signer driver") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type stubLeaseStore struct {
	renewLease leases.Lease
	renewOK    bool
	renewErr   error

	acquireLease leases.Lease
	acquireOK    bool
	acquireErr   error

	renewCalls   int
	acquireCalls int
}

func (s *stubLeaseStore) TryAcquire(_ context.Context, _ string, _ string, _ time.Duration) (leases.Lease, bool, error) {
	s.acquireCalls++
	return s.acquireLease, s.acquireOK, s.acquireErr
}

func (s *stubLeaseStore) Renew(_ context.Context, _ string, _ string, _ time.Duration) (leases.Lease, bool, error) {
	s.renewCalls++
	return s.renewLease, s.renewOK, s.renewErr
}

func (s *stubLeaseStore) Release(_ context.Context, _ string, _ string) error {
	return nil
}

func (s *stubLeaseStore) Get(_ context.Context, _ string) (leases.Lease, error) {
	return leases.Lease{}, leases.ErrNotFound
}

func TestHoldLease_ReacquiresExpiredLease(t *testing.T) {
	t.Parallel()

	store := &stubLeaseStore{
		renewErr:   leases.ErrExpired,
		acquireOK:  true,
		acquireLease: leases.Lease{
			Name:      "checkpoint-signer",
			Owner:     "node-a",
			Version:   2,
			ExpiresAt: time.Now().Add(15 * time.Second),
		},
	}

	ok, err := holdLease(context.Background(), store, "checkpoint-signer", "node-a", 15*time.Second)
	if err != nil {
		t.Fatalf("holdLease: %v", err)
	}
	if !ok {
		t.Fatalf("expected lease reacquire to succeed")
	}
	if store.renewCalls != 1 {
		t.Fatalf("renew calls: got %d want 1", store.renewCalls)
	}
	if store.acquireCalls != 1 {
		t.Fatalf("acquire calls: got %d want 1", store.acquireCalls)
	}
}

func TestHoldLease_PropagatesUnexpectedRenewError(t *testing.T) {
	t.Parallel()

	store := &stubLeaseStore{
		renewErr: errors.New("boom"),
	}

	ok, err := holdLease(context.Background(), store, "checkpoint-signer", "node-a", 15*time.Second)
	if err == nil {
		t.Fatalf("expected error")
	}
	if ok {
		t.Fatalf("expected no leadership on unexpected error")
	}
	if store.acquireCalls != 0 {
		t.Fatalf("acquire calls: got %d want 0", store.acquireCalls)
	}
}
