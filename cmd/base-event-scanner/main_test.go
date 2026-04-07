package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestEventPayload_CoordinatorCompat verifies that eventPayload marshals to JSON
// that is compatible with the withdraw coordinator's withdrawRequestedV1 struct.
func TestEventPayload_CoordinatorCompat(t *testing.T) {
	t.Parallel()

	// coordinatorMsg mirrors the fields cmd/withdraw-coordinator requires from withdrawRequestedV2.
	type coordinatorMsg struct {
		Version        string `json:"version"`
		WithdrawalID   string `json:"withdrawalId"`
		Requester      string `json:"requester"`
		Amount         uint64 `json:"amount"`
		RecipientUA    string `json:"recipientUA"`
		Expiry         uint64 `json:"expiry"`
		FeeBps         uint32 `json:"feeBps"`
		BlockNumber    uint64 `json:"blockNumber"`
		BlockHash      string `json:"blockHash"`
		TxHash         string `json:"txHash"`
		LogIndex       uint   `json:"logIndex"`
		FinalitySource string `json:"finalitySource"`
	}

	src := eventPayload{
		Version:        "withdrawals.requested.v2",
		WithdrawalID:   "0xaabbccdd",
		Requester:      "0x1111111111111111111111111111111111111111",
		Amount:         42000,
		RecipientUA:    "0x" + "ff",
		Expiry:         1700000000,
		FeeBps:         50,
		BlockNumber:    123,
		BlockHash:      "0xabc123",
		TxHash:         "0xdeadbeef",
		LogIndex:       7,
		FinalitySource: "safe",
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
	if dst.BlockNumber != src.BlockNumber {
		t.Errorf("blockNumber: got %d want %d", dst.BlockNumber, src.BlockNumber)
	}
	if dst.BlockHash != src.BlockHash {
		t.Errorf("blockHash: got %q want %q", dst.BlockHash, src.BlockHash)
	}
	if dst.TxHash != src.TxHash {
		t.Errorf("txHash: got %q want %q", dst.TxHash, src.TxHash)
	}
	if dst.LogIndex != src.LogIndex {
		t.Errorf("logIndex: got %d want %d", dst.LogIndex, src.LogIndex)
	}
	if dst.FinalitySource != src.FinalitySource {
		t.Errorf("finalitySource: got %q want %q", dst.FinalitySource, src.FinalitySource)
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

func TestEnsureScannerQueueTopics(t *testing.T) {
	original := ensureBaseEventScannerKafkaTopics
	t.Cleanup(func() {
		ensureBaseEventScannerKafkaTopics = original
	})

	tests := []struct {
		name          string
		driver        string
		brokers       string
		topics        string
		wantCalled    bool
		wantBrokers   []string
		wantTopics    []string
		injectedErr   error
		wantErrSubstr string
	}{
		{
			name:        "kafka ensures withdraw topic",
			driver:      "kafka",
			brokers:     "broker-a:9092, broker-b:9092",
			topics:      "withdrawals.requested.v2",
			wantCalled:  true,
			wantBrokers: []string{"broker-a:9092", "broker-b:9092"},
			wantTopics:  []string{"withdrawals.requested.v2"},
		},
		{
			name:       "stdio skips topic creation",
			driver:     "stdio",
			brokers:    "broker-a:9092",
			topics:     "withdrawals.requested.v2",
			wantCalled: false,
		},
		{
			name:          "propagates kafka error",
			driver:        "kafka",
			brokers:       "broker-a:9092",
			topics:        "withdrawals.requested.v2",
			wantCalled:    true,
			wantBrokers:   []string{"broker-a:9092"},
			wantTopics:    []string{"withdrawals.requested.v2"},
			injectedErr:   errors.New("boom"),
			wantErrSubstr: "boom",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			var gotBrokers []string
			var gotTopics []string
			ensureBaseEventScannerKafkaTopics = func(_ context.Context, brokers []string, topics []string) error {
				called = true
				gotBrokers = append([]string(nil), brokers...)
				gotTopics = append([]string(nil), topics...)
				return tc.injectedErr
			}

			err := ensureScannerQueueTopics(context.Background(), tc.driver, tc.brokers, tc.topics)
			if tc.wantErrSubstr == "" {
				if err != nil {
					t.Fatalf("ensureScannerQueueTopics: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Fatalf("ensureScannerQueueTopics error = %v, want substring %q", err, tc.wantErrSubstr)
				}
			}
			if called != tc.wantCalled {
				t.Fatalf("ensure topic call = %v want %v", called, tc.wantCalled)
			}
			if tc.wantCalled && !reflect.DeepEqual(gotBrokers, tc.wantBrokers) {
				t.Fatalf("brokers = %#v want %#v", gotBrokers, tc.wantBrokers)
			}
			if tc.wantCalled && !reflect.DeepEqual(gotTopics, tc.wantTopics) {
				t.Fatalf("topics = %#v want %#v", gotTopics, tc.wantTopics)
			}
		})
	}
}
