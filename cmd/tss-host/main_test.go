package main

import (
	"context"
	"errors"
	"testing"
)

func TestMultiValueFlag_SetRejectsBlank(t *testing.T) {
	t.Parallel()

	var f multiValueFlag
	if err := f.Set(" "); err == nil {
		t.Fatalf("expected blank value rejection")
	}
}

func TestMultiValueFlag_ValuesReturnsCopy(t *testing.T) {
	t.Parallel()

	var f multiValueFlag
	if err := f.Set("--foo"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := f.Set("bar"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	values := f.Values()
	if len(values) != 2 {
		t.Fatalf("values length: got %d want 2", len(values))
	}
	values[0] = "mutated"

	fresh := f.Values()
	if fresh[0] != "--foo" {
		t.Fatalf("Values must return copy, got %q", fresh[0])
	}
}

type stubReadySigner struct {
	err error
}

func (s stubReadySigner) Ready(context.Context) error {
	return s.err
}

func TestSignerReadinessCheck_UsesReadyMethod(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("signer not ready")
	check := signerReadinessCheck(stubReadySigner{err: wantErr})
	if check == nil {
		t.Fatalf("expected readiness check")
	}
	if err := check(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("check err = %v, want %v", err, wantErr)
	}
}

func TestSignerReadinessCheck_IgnoresSignersWithoutReadyMethod(t *testing.T) {
	t.Parallel()

	if check := signerReadinessCheck(struct{}{}); check != nil {
		t.Fatalf("expected nil readiness check for signer without Ready method")
	}
}
