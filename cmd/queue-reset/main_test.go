package main

import (
	"testing"
)

func TestParseFlags_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "no flags",
			args:    nil,
			wantErr: true,
		},
		{
			name:    "missing brokers",
			args:    []string{"--group", "g1", "--topic", "t1"},
			wantErr: true,
		},
		{
			name:    "missing group",
			args:    []string{"--brokers", "localhost:9092", "--topic", "t1"},
			wantErr: true,
		},
		{
			name:    "missing topic",
			args:    []string{"--brokers", "localhost:9092", "--group", "g1"},
			wantErr: true,
		},
		{
			name: "conflicting modes",
			args: []string{
				"--brokers", "localhost:9092",
				"--group", "g1",
				"--topic", "t1",
				"--to-beginning",
				"--to-latest",
			},
			wantErr: true,
		},
		{
			name: "dry-run without mode is ok",
			args: []string{
				"--brokers", "localhost:9092",
				"--group", "g1",
				"--topic", "t1",
			},
			wantErr: false,
		},
		{
			name: "dry-run=false without mode errors",
			args: []string{
				"--brokers", "localhost:9092",
				"--group", "g1",
				"--topic", "t1",
				"--dry-run=false",
			},
			wantErr: true,
		},
		{
			name: "to-beginning valid",
			args: []string{
				"--brokers", "localhost:9092",
				"--group", "g1",
				"--topic", "t1",
				"--to-beginning",
			},
			wantErr: false,
		},
		{
			name: "to-latest valid",
			args: []string{
				"--brokers", "localhost:9092",
				"--group", "g1",
				"--topic", "t1",
				"--to-latest",
			},
			wantErr: false,
		},
		{
			name: "to-offset valid",
			args: []string{
				"--brokers", "localhost:9092",
				"--group", "g1",
				"--topic", "t1",
				"--to-offset", "42",
			},
			wantErr: false,
		},
		{
			name: "multiple brokers valid",
			args: []string{
				"--brokers", "b1:9092,b2:9092",
				"--group", "g1",
				"--topic", "t1",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := parseFlags(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFlags: %v", err)
			}
			_ = cfg
		})
	}
}

func TestParseFlags_Values(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		args         []string
		wantBrokers  int
		wantGroup    string
		wantTopic    string
		wantMode     resetMode
		wantOffset   int64
		wantDryRun   bool
	}{
		{
			name:        "dry-run to-beginning",
			args:        []string{"--brokers", "b1:9092", "--group", "my-group", "--topic", "my-topic", "--to-beginning"},
			wantBrokers: 1,
			wantGroup:   "my-group",
			wantTopic:   "my-topic",
			wantMode:    resetModeBeginning,
			wantDryRun:  true,
		},
		{
			name:        "to-offset with dry-run=false",
			args:        []string{"--brokers", "b1:9092,b2:9092", "--group", "g2", "--topic", "t2", "--to-offset", "100", "--dry-run=false"},
			wantBrokers: 2,
			wantGroup:   "g2",
			wantTopic:   "t2",
			wantMode:    resetModeOffset,
			wantOffset:  100,
			wantDryRun:  false,
		},
		{
			name:        "default dry-run no mode",
			args:        []string{"--brokers", "b1:9092", "--group", "g3", "--topic", "t3"},
			wantBrokers: 1,
			wantGroup:   "g3",
			wantTopic:   "t3",
			wantMode:    resetModeNone,
			wantDryRun:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := parseFlags(tt.args)
			if err != nil {
				t.Fatalf("parseFlags: %v", err)
			}
			if len(cfg.brokers) != tt.wantBrokers {
				t.Fatalf("brokers: got=%d want=%d", len(cfg.brokers), tt.wantBrokers)
			}
			if cfg.group != tt.wantGroup {
				t.Fatalf("group: got=%q want=%q", cfg.group, tt.wantGroup)
			}
			if cfg.topic != tt.wantTopic {
				t.Fatalf("topic: got=%q want=%q", cfg.topic, tt.wantTopic)
			}
			if cfg.mode != tt.wantMode {
				t.Fatalf("mode: got=%d want=%d", cfg.mode, tt.wantMode)
			}
			if cfg.targetOffset != tt.wantOffset {
				t.Fatalf("targetOffset: got=%d want=%d", cfg.targetOffset, tt.wantOffset)
			}
			if cfg.dryRun != tt.wantDryRun {
				t.Fatalf("dryRun: got=%v want=%v", cfg.dryRun, tt.wantDryRun)
			}
		})
	}
}

func TestSplitCommaList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"  ", 0},
		{"a", 1},
		{"a,b", 2},
		{" a , b , c ", 3},
		{"a,,b", 2},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := splitCommaList(tt.input)
			if len(got) != tt.want {
				t.Fatalf("splitCommaList(%q): got=%d want=%d", tt.input, len(got), tt.want)
			}
		})
	}
}

func TestModeName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode   resetMode
		offset int64
		want   string
	}{
		{resetModeBeginning, 0, "beginning (earliest)"},
		{resetModeLatest, 0, "latest"},
		{resetModeOffset, 42, "offset 42"},
		{resetModeNone, 0, "none"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			got := modeName(tt.mode, tt.offset)
			if got != tt.want {
				t.Fatalf("modeName: got=%q want=%q", got, tt.want)
			}
		})
	}
}
