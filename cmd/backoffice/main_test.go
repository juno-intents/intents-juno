package main

import (
	"context"
	"errors"
	"math/big"
	"testing"
)

type stubChainIDReader struct {
	calls int
	err   error
}

func (s *stubChainIDReader) ChainID(context.Context) (*big.Int, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return big.NewInt(8453), nil
}

func TestChainReadinessCheck(t *testing.T) {
	t.Parallel()

	reader := &stubChainIDReader{}
	check := chainReadinessCheck(reader)
	if err := check(context.Background()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if reader.calls != 1 {
		t.Fatalf("calls: got %d want 1", reader.calls)
	}
}

func TestChainReadinessCheck_PropagatesFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("base rpc down")
	check := chainReadinessCheck(&stubChainIDReader{err: wantErr})
	if err := check(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("error: got %v want %v", err, wantErr)
	}
}
