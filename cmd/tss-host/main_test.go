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

func TestValidateSecureTSSHostConfig(t *testing.T) {
	t.Parallel()

	valid := secureTSSHostConfig{
		ListenAddr:   "127.0.0.1:9443",
		ClientCAFile: "/tmp/ca.pem",
		AuthToken:    "secret",
		BaseChainID:  8453,
		BridgeAddr:   "0x1111111111111111111111111111111111111111",
		PostgresDSN:  "postgres://example?sslmode=require",
	}

	if err := validateSecureTSSHostConfig(valid); err != nil {
		t.Fatalf("validateSecureTSSHostConfig(valid): %v", err)
	}

	invalid := valid
	invalid.ClientCAFile = ""
	if err := validateSecureTSSHostConfig(invalid); err == nil {
		t.Fatalf("expected missing client CA to fail")
	}

	invalid = valid
	invalid.AuthToken = ""
	if err := validateSecureTSSHostConfig(invalid); err == nil {
		t.Fatalf("expected missing auth token to fail")
	}
}
