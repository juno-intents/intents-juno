package pgxpoolutil

import (
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestApply(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		settings    Settings
		wantMin     int32
		wantMax     int32
		wantLife    time.Duration
		wantIdle    time.Duration
		wantHealth  time.Duration
		wantErrText string
	}{
		{
			name:       "defaults",
			settings:   Settings{},
			wantMin:    DefaultMinConns,
			wantMax:    DefaultMaxConns,
			wantLife:   DefaultMaxConnLifetime,
			wantIdle:   DefaultMaxConnIdleTime,
			wantHealth: DefaultHealthCheckPeriod,
		},
		{
			name: "custom values",
			settings: Settings{
				MinConns:          3,
				MaxConns:          11,
				MaxConnLifetime:   45 * time.Minute,
				MaxConnIdleTime:   12 * time.Minute,
				HealthCheckPeriod: 15 * time.Second,
			},
			wantMin:    3,
			wantMax:    11,
			wantLife:   45 * time.Minute,
			wantIdle:   12 * time.Minute,
			wantHealth: 15 * time.Second,
		},
		{
			name: "max below min",
			settings: Settings{
				MinConns: 5,
				MaxConns: 4,
			},
			wantErrText: "must be >=",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := pgxpool.ParseConfig("postgres://user:pass@localhost:5432/test")
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}

			err = Apply(cfg, tc.settings)
			if tc.wantErrText != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tc.wantErrText) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantErrText)
				}
				return
			}
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}

			if cfg.MinConns != tc.wantMin {
				t.Fatalf("MinConns = %d, want %d", cfg.MinConns, tc.wantMin)
			}
			if cfg.MaxConns != tc.wantMax {
				t.Fatalf("MaxConns = %d, want %d", cfg.MaxConns, tc.wantMax)
			}
			if cfg.MaxConnLifetime != tc.wantLife {
				t.Fatalf("MaxConnLifetime = %s, want %s", cfg.MaxConnLifetime, tc.wantLife)
			}
			if cfg.MaxConnIdleTime != tc.wantIdle {
				t.Fatalf("MaxConnIdleTime = %s, want %s", cfg.MaxConnIdleTime, tc.wantIdle)
			}
			if cfg.HealthCheckPeriod != tc.wantHealth {
				t.Fatalf("HealthCheckPeriod = %s, want %s", cfg.HealthCheckPeriod, tc.wantHealth)
			}
		})
	}
}

func TestParseConfigRejectsNilSettings(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfig("postgres://user:pass@localhost:5432/test", Settings{
		MinConns: 4,
		MaxConns: 3,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if cfg != nil {
		t.Fatal("expected nil config on error")
	}
}
