package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/juno-intents/intents-juno/internal/withdraw"
)

func TestNormalizeRuntimeMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		want        string
		wantErr     bool
		errContains string
	}{
		{name: "default", input: "", want: runtimeModeFull},
		{name: "full", input: "full", want: runtimeModeFull},
		{name: "mock is rejected", input: "mock", wantErr: true, errContains: "not supported"},
		{name: "mixed case mock is rejected", input: " MoCk ", wantErr: true, errContains: "not supported"},
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
				if tc.errContains != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.errContains)) {
					t.Fatalf("error mismatch: got=%q want_contains=%q", err.Error(), tc.errContains)
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

func TestNewTSSHTTPClient_ServerName(t *testing.T) {
	t.Parallel()

	client, err := newTSSHTTPClient(5*time.Second, "", "", "", "10.0.0.141")
	if err != nil {
		t.Fatalf("newTSSHTTPClient: %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatalf("expected TLS client config")
	}
	if transport.TLSClientConfig.ServerName != "10.0.0.141" {
		t.Fatalf("server name mismatch: got=%q want=%q", transport.TLSClientConfig.ServerName, "10.0.0.141")
	}
}

func TestShouldAckWithdrawIngestError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "permanent invalid config", err: withdraw.ErrInvalidConfig, want: true},
		{name: "permanent mismatch", err: withdraw.ErrWithdrawalMismatch, want: true},
		{name: "transient other", err: errors.New("db unavailable"), want: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldAckWithdrawIngestError(tc.err); got != tc.want {
				t.Fatalf("shouldAckWithdrawIngestError(%v) = %v want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestParseWithdrawRequestedMessage_AcceptsV2(t *testing.T) {
	t.Parallel()

	line, err := json.Marshal(map[string]any{
		"version":        "withdrawals.requested.v2",
		"withdrawalId":   "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"requester":      "0x1111111111111111111111111111111111111111",
		"amount":         42000,
		"recipientUA":    "0x" + strings.Repeat("11", 43),
		"expiry":         1700000000,
		"feeBps":         50,
		"blockNumber":    123,
		"blockHash":      "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"txHash":         "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"logIndex":       7,
		"finalitySource": "safe",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	msg, err := parseWithdrawRequestedMessage(line)
	if err != nil {
		t.Fatalf("parseWithdrawRequestedMessage: %v", err)
	}
	if msg.Version != "withdrawals.requested.v2" {
		t.Fatalf("Version = %q", msg.Version)
	}
	if msg.BlockHash != "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("BlockHash = %q", msg.BlockHash)
	}
	if msg.FinalitySource != "safe" {
		t.Fatalf("FinalitySource = %q", msg.FinalitySource)
	}
}

func TestParseWithdrawRequestedMessage_RejectsV2WithoutTxHash(t *testing.T) {
	t.Parallel()

	line, err := json.Marshal(map[string]any{
		"version":        "withdrawals.requested.v2",
		"withdrawalId":   "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"requester":      "0x1111111111111111111111111111111111111111",
		"amount":         42000,
		"recipientUA":    "0x" + strings.Repeat("11", 43),
		"expiry":         1700000000,
		"feeBps":         50,
		"blockNumber":    123,
		"blockHash":      "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"logIndex":       7,
		"finalitySource": "safe",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := parseWithdrawRequestedMessage(line); err == nil || !strings.Contains(err.Error(), "missing txHash") {
		t.Fatalf("expected missing txHash error, got %v", err)
	}
}

func TestParseWithdrawRequestedMessage_RejectsUnknownFinalitySource(t *testing.T) {
	t.Parallel()

	line, err := json.Marshal(map[string]any{
		"version":        "withdrawals.requested.v2",
		"withdrawalId":   "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"requester":      "0x1111111111111111111111111111111111111111",
		"amount":         42000,
		"recipientUA":    "0x" + strings.Repeat("11", 43),
		"expiry":         1700000000,
		"feeBps":         50,
		"blockNumber":    123,
		"blockHash":      "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"txHash":         "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"logIndex":       7,
		"finalitySource": "direct-receipt",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := parseWithdrawRequestedMessage(line); err == nil || !strings.Contains(err.Error(), "invalid finalitySource") {
		t.Fatalf("expected invalid finalitySource error, got %v", err)
	}
}

func TestParseWithdrawRequestedMessage_RejectsLegacyV1(t *testing.T) {
	t.Parallel()

	line, err := json.Marshal(map[string]any{
		"version":      "withdrawals.requested.v1",
		"withdrawalId": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"requester":    "0x1111111111111111111111111111111111111111",
		"amount":       42000,
		"recipientUA":  "0x" + strings.Repeat("11", 43),
		"expiry":       1700000000,
		"feeBps":       50,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := parseWithdrawRequestedMessage(line); err == nil || !strings.Contains(err.Error(), "legacy message version") {
		t.Fatalf("expected legacy message version error, got %v", err)
	}
}
