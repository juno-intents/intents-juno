package main

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/juno-intents/intents-juno/internal/withdraw"
)

func TestNormalizeRuntimeMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "default", input: "", want: runtimeModeFull},
		{name: "full", input: "full", want: runtimeModeFull},
		{name: "mock", input: "mock", want: runtimeModeMock},
		{name: "mixed case", input: " MoCk ", want: runtimeModeMock},
		{name: "invalid", input: "other", wantErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeRuntimeMode(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeRuntimeMode: %v", err)
			}
			if got != tc.want {
				t.Fatalf("mode mismatch: got=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestMockCoordinatorComponents(t *testing.T) {
	t.Parallel()

	planner := mockPlanner{}
	signer := mockSigner{}
	broadcaster := mockBroadcaster{}
	confirmer := mockConfirmer{}

	batchID := [32]byte{1, 2, 3}
	plan, err := planner.Plan(context.Background(), batchID, []withdraw.Withdrawal{{ID: [32]byte{9}}})
	if err != nil {
		t.Fatalf("mock planner: %v", err)
	}
	if string(plan) == "" {
		t.Fatalf("mock planner returned empty plan")
	}

	sessionID := [32]byte{4, 5, 6}
	signed, err := signer.Sign(context.Background(), sessionID, plan)
	if err != nil {
		t.Fatalf("mock signer: %v", err)
	}
	if string(signed) == "" {
		t.Fatalf("mock signer returned empty signed tx")
	}

	txid, err := broadcaster.Broadcast(context.Background(), signed)
	if err != nil {
		t.Fatalf("mock broadcaster: %v", err)
	}
	if _, err := hex.DecodeString(txid); err != nil {
		t.Fatalf("mock broadcaster txid should be hex: %v", err)
	}

	if err := confirmer.WaitConfirmed(context.Background(), txid); err != nil {
		t.Fatalf("mock confirmer: %v", err)
	}
}
