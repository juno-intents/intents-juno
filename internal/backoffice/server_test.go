package backoffice

import (
	"testing"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNewAppliesRateLimitDefaults(t *testing.T) {
	t.Parallel()

	s, err := New(ServerConfig{
		Pool:       &pgxpool.Pool{},
		BaseClient: &ethclient.Client{},
		AuthSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := s.cfg.RateLimitPerSecond; got != 15 {
		t.Fatalf("RateLimitPerSecond = %v, want 15", got)
	}
	if got := s.cfg.RateLimitBurst; got != 30 {
		t.Fatalf("RateLimitBurst = %d, want 30", got)
	}
}
