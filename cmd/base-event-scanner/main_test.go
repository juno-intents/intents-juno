package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestEventPayload_CoordinatorCompat verifies that eventPayload marshals to JSON
// that is compatible with the withdraw coordinator's withdrawRequestedV1 struct.
func TestEventPayload_CoordinatorCompat(t *testing.T) {
	t.Parallel()

	// coordinatorMsg mirrors cmd/withdraw-coordinator withdrawRequestedV1.
	type coordinatorMsg struct {
		Version      string `json:"version"`
		WithdrawalID string `json:"withdrawalId"`
		Requester    string `json:"requester"`
		Amount       uint64 `json:"amount"`
		RecipientUA  string `json:"recipientUA"`
		Expiry       uint64 `json:"expiry"`
		FeeBps       uint32 `json:"feeBps"`
	}

	src := eventPayload{
		Version:      "withdrawals.requested.v1",
		WithdrawalID: "0xaabbccdd",
		Requester:    "0x1111111111111111111111111111111111111111",
		Amount:       42000,
		RecipientUA:  "0x" + "ff",
		Expiry:       1700000000,
		FeeBps:       50,
		BlockNumber:  123,
		TxHash:       "0xdeadbeef",
		LogIndex:     7,
	}

	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("marshal eventPayload: %v", err)
	}

	var dst coordinatorMsg
	if err := json.Unmarshal(raw, &dst); err != nil {
		t.Fatalf("unmarshal into coordinator struct: %v", err)
	}

	if dst.Version != src.Version {
		t.Errorf("version: got %q want %q", dst.Version, src.Version)
	}
	if dst.WithdrawalID != src.WithdrawalID {
		t.Errorf("withdrawalId: got %q want %q", dst.WithdrawalID, src.WithdrawalID)
	}
	if dst.Requester != src.Requester {
		t.Errorf("requester: got %q want %q", dst.Requester, src.Requester)
	}
	if dst.Amount != src.Amount {
		t.Errorf("amount: got %d want %d", dst.Amount, src.Amount)
	}
	if dst.RecipientUA != src.RecipientUA {
		t.Errorf("recipientUA: got %q want %q", dst.RecipientUA, src.RecipientUA)
	}
	if dst.Expiry != src.Expiry {
		t.Errorf("expiry: got %d want %d", dst.Expiry, src.Expiry)
	}
	if dst.FeeBps != src.FeeBps {
		t.Errorf("feeBps: got %d want %d", dst.FeeBps, src.FeeBps)
	}
}

func TestRunMain_MissingRequiredFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "no flags",
			args: nil,
		},
		{
			name: "missing bridge-address",
			args: []string{"--base-rpc-url", "http://localhost:8545", "--postgres-dsn", "postgres://localhost/test"},
		},
		{
			name: "missing postgres-dsn",
			args: []string{"--base-rpc-url", "http://localhost:8545", "--bridge-address", "0x1234567890abcdef1234567890abcdef12345678"},
		},
		{
			name: "missing base-rpc-url",
			args: []string{"--bridge-address", "0x1234567890abcdef1234567890abcdef12345678", "--postgres-dsn", "postgres://localhost/test"},
		},
		{
			name: "invalid bridge-address",
			args: []string{"--base-rpc-url", "http://localhost:8545", "--bridge-address", "not-an-address", "--postgres-dsn", "postgres://localhost/test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			err := runMain(tt.args, &out)
			if err == nil {
				t.Fatal("expected error for missing/invalid required flags")
			}
		})
	}
}
