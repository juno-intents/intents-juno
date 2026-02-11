package boundless

import (
	"errors"
	"testing"
)

func TestParseBackend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    Backend
		wantErr bool
	}{
		{name: "boundless", in: "boundless", want: BackendBoundless},
		{name: "self", in: "self", want: BackendSelf},
		{name: "trim and lower", in: "  SeLf\t", want: BackendSelf},
		{name: "missing", in: "", wantErr: true},
		{name: "unknown", in: "gpu", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseBackend(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseBackend(%q): expected error", tt.in)
				}
				if !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("ParseBackend(%q): expected ErrInvalidConfig, got %v", tt.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBackend(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("ParseBackend(%q): got %q want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "defaults to boundless",
			cfg: Config{
				ProverBin:        "fake-prover",
				MaxResponseBytes: 1024,
			},
		},
		{
			name: "self backend",
			cfg: Config{
				Backend:          BackendSelf.String(),
				ProverBin:        "fake-prover",
				MaxResponseBytes: 1024,
			},
		},
		{
			name: "unknown backend",
			cfg: Config{
				Backend:          "gpu",
				ProverBin:        "fake-prover",
				MaxResponseBytes: 1024,
			},
			wantErr: true,
		},
		{
			name: "missing prover binary",
			cfg: Config{
				Backend:          BackendBoundless.String(),
				MaxResponseBytes: 1024,
			},
			wantErr: true,
		},
		{
			name: "invalid response limit",
			cfg: Config{
				Backend:          BackendBoundless.String(),
				ProverBin:        "fake-prover",
				MaxResponseBytes: 0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client, err := New(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("New(%+v): expected error", tt.cfg)
				}
				if !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("New(%+v): expected ErrInvalidConfig, got %v", tt.cfg, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%+v): %v", tt.cfg, err)
			}
			if client == nil {
				t.Fatalf("New(%+v): nil client", tt.cfg)
			}
		})
	}
}
