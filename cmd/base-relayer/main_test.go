package main

import "testing"

func TestParseConfig_RequiresTLSKeyPairTogether(t *testing.T) {
	t.Parallel()

	_, err := parseConfig([]string{
		"--rpc-url", "http://127.0.0.1:8545",
		"--chain-id", "8453",
		"--tls-cert-file", "/tmp/server.pem",
	})
	if err == nil {
		t.Fatalf("expected tls config validation error")
	}

	_, err = parseConfig([]string{
		"--rpc-url", "http://127.0.0.1:8545",
		"--chain-id", "8453",
		"--tls-key-file", "/tmp/server.key",
	})
	if err == nil {
		t.Fatalf("expected tls config validation error")
	}
}

func TestParseConfig_ParsesIngressHardeningFlags(t *testing.T) {
	t.Parallel()

	cfg, err := parseConfig([]string{
		"--rpc-url", "http://127.0.0.1:8545",
		"--chain-id", "8453",
		"--allowed-contracts", "0x0000000000000000000000000000000000000001,0x0000000000000000000000000000000000000002",
		"--tls-cert-file", "/tmp/server.pem",
		"--tls-key-file", "/tmp/server.key",
		"--rate-limit-per-second", "5",
		"--rate-limit-burst", "7",
		"--rate-limit-max-tracked-clients", "11",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.TLSCertFile != "/tmp/server.pem" || cfg.TLSKeyFile != "/tmp/server.key" {
		t.Fatalf("tls files not parsed: %+v", cfg)
	}
	if cfg.RateLimitPerSecond != 5 || cfg.RateLimitBurst != 7 || cfg.RateLimitMaxTrackedClients != 11 {
		t.Fatalf("rate limit settings not parsed: %+v", cfg)
	}
	if len(cfg.AllowedContracts) != 2 {
		t.Fatalf("allowed contracts: got %d want 2", len(cfg.AllowedContracts))
	}
}

func TestParseConfig_RequiresAllowedContracts(t *testing.T) {
	t.Parallel()

	_, err := parseConfig([]string{
		"--rpc-url", "http://127.0.0.1:8545",
		"--chain-id", "8453",
	})
	if err == nil {
		t.Fatal("expected allowed contracts validation error")
	}
}
