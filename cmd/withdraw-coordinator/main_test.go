package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
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
