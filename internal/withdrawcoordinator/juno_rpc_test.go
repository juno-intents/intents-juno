package withdrawcoordinator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/juno-intents/intents-juno/internal/junorpc"
)

type stubJunoRPC struct {
	sendTxID string
	sendErr  error

	getCalls int
	getSeq   []getResult
}

type getResult struct {
	tx  junorpc.RawTransaction
	err error
}

func (s *stubJunoRPC) SendRawTransaction(_ context.Context, _ []byte) (string, error) {
	return s.sendTxID, s.sendErr
}

func (s *stubJunoRPC) GetRawTransaction(_ context.Context, _ string) (junorpc.RawTransaction, error) {
	if s.getCalls >= len(s.getSeq) {
		return junorpc.RawTransaction{}, junorpc.ErrTxNotFound
	}
	out := s.getSeq[s.getCalls]
	s.getCalls++
	return out.tx, out.err
}

func TestJunoBroadcaster_Broadcast(t *testing.T) {
	t.Parallel()

	b, err := NewJunoBroadcaster(&stubJunoRPC{sendTxID: "abc"})
	if err != nil {
		t.Fatalf("NewJunoBroadcaster: %v", err)
	}
	txid, err := b.Broadcast(context.Background(), []byte{0x01})
	if err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	if txid != "abc" {
		t.Fatalf("txid: got %q want %q", txid, "abc")
	}
}

func TestJunoConfirmer_WaitsForMinConfirmations(t *testing.T) {
	t.Parallel()

	rpc := &stubJunoRPC{
		getSeq: []getResult{
			{err: junorpc.ErrTxNotFound},
			{tx: junorpc.RawTransaction{TxID: "a", Confirmations: 0}},
			{tx: junorpc.RawTransaction{TxID: "a", Confirmations: 2}},
		},
	}
	c, err := NewJunoConfirmer(rpc, 2, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("NewJunoConfirmer: %v", err)
	}
	if err := c.WaitConfirmed(context.Background(), "a"); err != nil {
		t.Fatalf("WaitConfirmed: %v", err)
	}
	if rpc.getCalls != 3 {
		t.Fatalf("getCalls: got %d want %d", rpc.getCalls, 3)
	}
}

func TestJunoConfirmer_ReturnsUnexpectedError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("rpc down")
	rpc := &stubJunoRPC{
		getSeq: []getResult{
			{err: wantErr},
		},
	}
	c, err := NewJunoConfirmer(rpc, 1, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("NewJunoConfirmer: %v", err)
	}
	if err := c.WaitConfirmed(context.Background(), "a"); !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
}

func TestNewJunoConfirmer_RejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	_, err := NewJunoConfirmer(nil, 1, 1*time.Second)
	if !errors.Is(err, ErrInvalidJunoRuntimeConfig) {
		t.Fatalf("expected ErrInvalidJunoRuntimeConfig, got %v", err)
	}
}
