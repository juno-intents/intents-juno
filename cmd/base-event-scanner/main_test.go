package main

import (
	"bytes"
	"testing"
)

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
