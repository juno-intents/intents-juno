package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type stubReadyDependency struct {
	calls int
	err   error
}

func (s *stubReadyDependency) Ready(context.Context) error {
	s.calls++
	return s.err
}

type fakeDialConn struct {
	closed bool
}

func (c *fakeDialConn) Close() error {
	c.closed = true
	return nil
}

func TestReadyCheckFromDependency_UsesReady(t *testing.T) {
	t.Parallel()

	dep := &stubReadyDependency{}
	check := readyCheckFromDependency(dep)
	if check == nil {
		t.Fatalf("expected readiness check")
	}
	if err := check(context.Background()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if dep.calls != 1 {
		t.Fatalf("calls: got %d want 1", dep.calls)
	}
}

func TestProofRequestorReadinessCheck_ShortCircuitsOnDBFailure(t *testing.T) {
	t.Parallel()

	queueCalled := false
	proverCalled := false
	check := proofRequestorReadinessCheck(
		func(context.Context) error { return errors.New("db down") },
		func(context.Context) error {
			queueCalled = true
			return nil
		},
		func(context.Context) error {
			proverCalled = true
			return nil
		},
	)
	if check == nil {
		t.Fatalf("expected readiness check")
	}

	err := check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("unexpected err: %v", err)
	}
	if queueCalled || proverCalled {
		t.Fatalf("later checks should not run when db fails first")
	}
}

func TestProofRequestorReadinessCheck_RunsAllChecks(t *testing.T) {
	t.Parallel()

	order := make([]string, 0, 3)
	check := proofRequestorReadinessCheck(
		func(context.Context) error {
			order = append(order, "db")
			return nil
		},
		func(context.Context) error {
			order = append(order, "queue")
			return nil
		},
		func(context.Context) error {
			order = append(order, "prover")
			return nil
		},
	)

	if err := check(context.Background()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if got, want := strings.Join(order, ","), "db,queue,prover"; got != want {
		t.Fatalf("order: got %q want %q", got, want)
	}
}

func TestKafkaBrokerReadinessCheckWithDialer_SucceedsWhenAnyBrokerIsReachable(t *testing.T) {
	t.Parallel()

	var closedGood bool
	check := kafkaBrokerReadinessCheckWithDialer(
		[]string{"bad:9092", "good:9092"},
		func(_ context.Context, network, address string) (io.Closer, error) {
			if network != "tcp" {
				t.Fatalf("network: got %q want tcp", network)
			}
			if address == "bad:9092" {
				return nil, errors.New("dial failed")
			}
			conn := &fakeDialConn{}
			return closerFunc(func() error {
				closedGood = true
				return conn.Close()
			}), nil
		},
	)

	if err := check(context.Background()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if !closedGood {
		t.Fatalf("expected successful broker connection to close")
	}
}

func TestKafkaBrokerReadinessCheckWithDialer_FailsWhenAllBrokersFail(t *testing.T) {
	t.Parallel()

	check := kafkaBrokerReadinessCheckWithDialer(
		[]string{"bad-a:9092", "bad-b:9092"},
		func(context.Context, string, string) (io.Closer, error) {
			return nil, errors.New("dial failed")
		},
	)

	err := check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestKafkaBrokerReadinessCheckWithDialer_EmptyBrokersIsNoop(t *testing.T) {
	t.Parallel()

	if check := kafkaBrokerReadinessCheckWithDialer(nil, nil); check != nil {
		t.Fatalf("expected nil check")
	}
}

type closerFunc func() error

func (fn closerFunc) Close() error { return fn() }
