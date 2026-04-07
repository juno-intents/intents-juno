package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func TestValidateSecureTSSClientConfig(t *testing.T) {
	t.Parallel()

	valid := secureTSSClientConfig{
		URL:            "https://127.0.0.1:9443",
		ServerCAFile:   "/tmp/ca.pem",
		ClientCertFile: "/tmp/client.pem",
		ClientKeyFile:  "/tmp/client.key",
	}
	if err := validateSecureTSSClientConfig(valid); err != nil {
		t.Fatalf("validateSecureTSSClientConfig(valid): %v", err)
	}

	invalid := valid
	invalid.ServerCAFile = ""
	if err := validateSecureTSSClientConfig(invalid); err == nil {
		t.Fatalf("expected missing server CA to fail")
	}

	invalid = valid
	invalid.URL = "http://127.0.0.1:9443"
	if err := validateSecureTSSClientConfig(invalid); err == nil {
		t.Fatalf("expected non-https url to fail")
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

func TestStartTxBuildScanProxy_DisabledWhenScanURLBlank(t *testing.T) {
	t.Parallel()

	proxy, scanURL, err := startTxBuildScanProxy(context.Background(), " \t ")
	if err != nil {
		t.Fatalf("startTxBuildScanProxy: %v", err)
	}
	if proxy != nil {
		t.Fatalf("proxy: got %v want nil", proxy)
	}
	if scanURL != "" {
		t.Fatalf("scan URL: got %q want empty", scanURL)
	}
}

func TestStartTxBuildScanProxy_StartsForwardingProxy(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxy, scanURL, err := startTxBuildScanProxy(ctx, upstream.URL)
	if err != nil {
		t.Fatalf("startTxBuildScanProxy: %v", err)
	}
	if proxy == nil {
		t.Fatalf("proxy: got nil want non-nil")
	}
	if scanURL == "" || scanURL == upstream.URL {
		t.Fatalf("scan URL: got %q want proxy URL distinct from upstream %q", scanURL, upstream.URL)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := proxy.Close(shutdownCtx); err != nil {
			t.Fatalf("proxy close: %v", err)
		}
	}()

	resp, err := http.Get(scanURL + "/v1/health")
	if err != nil {
		t.Fatalf("proxy get: %v", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(raw) != `{"status":"ok"}` {
		t.Fatalf("body: got %q want %q", string(raw), `{"status":"ok"}`)
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

func TestEnsureCoordinatorQueueTopics(t *testing.T) {
	original := ensureWithdrawCoordinatorKafkaTopics
	t.Cleanup(func() {
		ensureWithdrawCoordinatorKafkaTopics = original
	})

	tests := []struct {
		name           string
		driver         string
		brokers        string
		topics         string
		wantCalled     bool
		wantBrokers    []string
		wantTopics     []string
		injectedErr    error
		wantErrSubstr  string
	}{
		{
			name:        "kafka ensures topics",
			driver:      "kafka",
			brokers:     "broker-a:9092, broker-b:9092",
			topics:      "withdrawals.requested.v2,ops.alerts.v1",
			wantCalled:  true,
			wantBrokers: []string{"broker-a:9092", "broker-b:9092"},
			wantTopics:  []string{"withdrawals.requested.v2", "ops.alerts.v1"},
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
			ensureWithdrawCoordinatorKafkaTopics = func(_ context.Context, brokers []string, topics []string) error {
				called = true
				gotBrokers = append([]string(nil), brokers...)
				gotTopics = append([]string(nil), topics...)
				return tc.injectedErr
			}

			err := ensureCoordinatorQueueTopics(context.Background(), tc.driver, tc.brokers, tc.topics)
			if tc.wantErrSubstr == "" {
				if err != nil {
					t.Fatalf("ensureCoordinatorQueueTopics: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Fatalf("ensureCoordinatorQueueTopics error = %v, want substring %q", err, tc.wantErrSubstr)
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

func TestParseWithdrawRequestedMessage_RejectsZeroBlockHash(t *testing.T) {
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
		"blockHash":      "0x" + strings.Repeat("00", 32),
		"txHash":         "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"logIndex":       7,
		"finalitySource": "safe",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := parseWithdrawRequestedMessage(line); err == nil || !strings.Contains(err.Error(), "zero blockHash") {
		t.Fatalf("expected zero blockHash error, got %v", err)
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
