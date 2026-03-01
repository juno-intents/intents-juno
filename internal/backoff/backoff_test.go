package backoff

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cfg         Config
		fn          func(calls *int) func(ctx context.Context) error
		wantErr     bool
		wantCalls   int
		wantNonRetr bool // expect non-retryable wrapping
	}{
		{
			name: "success on first try",
			cfg:  Config{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond},
			fn: func(calls *int) func(ctx context.Context) error {
				return func(ctx context.Context) error {
					*calls++
					return nil
				}
			},
			wantErr:   false,
			wantCalls: 1,
		},
		{
			name: "success on second try",
			cfg:  Config{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond},
			fn: func(calls *int) func(ctx context.Context) error {
				return func(ctx context.Context) error {
					*calls++
					if *calls < 2 {
						return IsRetryable(errors.New("transient"))
					}
					return nil
				}
			},
			wantErr:   false,
			wantCalls: 2,
		},
		{
			name: "exhausted attempts",
			cfg:  Config{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond},
			fn: func(calls *int) func(ctx context.Context) error {
				return func(ctx context.Context) error {
					*calls++
					return errors.New("always fails")
				}
			},
			wantErr:   true,
			wantCalls: 3,
		},
		{
			name: "non-retryable short-circuits",
			cfg:  Config{MaxAttempts: 10, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond},
			fn: func(calls *int) func(ctx context.Context) error {
				return func(ctx context.Context) error {
					*calls++
					return IsNonRetryable(errors.New("permanent"))
				}
			},
			wantErr:     true,
			wantCalls:   1,
			wantNonRetr: true,
		},
		{
			name: "unlimited attempts with eventual success",
			cfg:  Config{MaxAttempts: 0, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond},
			fn: func(calls *int) func(ctx context.Context) error {
				return func(ctx context.Context) error {
					*calls++
					if *calls < 5 {
						return errors.New("not yet")
					}
					return nil
				}
			},
			wantErr:   false,
			wantCalls: 5,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			ctx := context.Background()
			err := Retry(ctx, tt.cfg, tt.fn(&calls))
			if (err != nil) != tt.wantErr {
				t.Fatalf("Retry() error = %v, wantErr %v", err, tt.wantErr)
			}
			if calls != tt.wantCalls {
				t.Fatalf("Retry() calls = %d, want %d", calls, tt.wantCalls)
			}
			if tt.wantNonRetr && !IsMarkedNonRetryable(err) {
				t.Fatalf("expected non-retryable error, got %v", err)
			}
		})
	}
}

func TestRetry_ContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	calls := 0

	// Cancel after first call.
	fn := func(ctx context.Context) error {
		calls++
		if calls == 1 {
			cancel()
		}
		return errors.New("fail")
	}

	err := Retry(ctx, Config{
		MaxAttempts: 10,
		BaseDelay:   time.Millisecond,
		MaxDelay:    10 * time.Millisecond,
	}, fn)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call before cancellation, got %d", calls)
	}
}

func TestRetry_JitterBounds(t *testing.T) {
	t.Parallel()

	cfg := Config{
		MaxAttempts: 2,
		BaseDelay:   100 * time.Millisecond,
		MaxDelay:    1 * time.Second,
		Jitter:      0.5,
	}

	// Run multiple times to check jitter doesn't produce negative delays.
	for i := 0; i < 50; i++ {
		delay := computeDelay(cfg, 1)
		// With jitter=0.5 and BaseDelay=100ms, range is [50ms, 150ms].
		if delay < 0 {
			t.Fatalf("negative delay: %v", delay)
		}
		// Upper bound: BaseDelay + jitter * BaseDelay = 150ms
		if delay > 150*time.Millisecond {
			t.Fatalf("delay %v exceeds upper bound 150ms", delay)
		}
	}
}

func TestRetry_ExponentialGrowth(t *testing.T) {
	t.Parallel()

	cfg := Config{
		MaxAttempts: 10,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    1 * time.Second,
		Jitter:      0,
	}

	expected := []time.Duration{
		10 * time.Millisecond,  // attempt 1
		20 * time.Millisecond,  // attempt 2
		40 * time.Millisecond,  // attempt 3
		80 * time.Millisecond,  // attempt 4
		160 * time.Millisecond, // attempt 5
		320 * time.Millisecond, // attempt 6
		640 * time.Millisecond, // attempt 7
		1 * time.Second,        // attempt 8 (capped at MaxDelay)
	}

	for i, want := range expected {
		got := computeDelay(cfg, i+1)
		if got != want {
			t.Errorf("attempt %d: got %v, want %v", i+1, got, want)
		}
	}
}

func TestIsRetryable_IsNonRetryable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		err            error
		wantRetryable  bool
		wantNonRetryab bool
	}{
		{
			name:           "retryable wrapping",
			err:            IsRetryable(errors.New("temp")),
			wantRetryable:  true,
			wantNonRetryab: false,
		},
		{
			name:           "non-retryable wrapping",
			err:            IsNonRetryable(errors.New("perm")),
			wantRetryable:  false,
			wantNonRetryab: true,
		},
		{
			name:           "unmarked error",
			err:            errors.New("plain"),
			wantRetryable:  false,
			wantNonRetryab: false,
		},
		{
			name:           "nil retryable",
			err:            IsRetryable(nil),
			wantRetryable:  false,
			wantNonRetryab: false,
		},
		{
			name:           "nil non-retryable",
			err:            IsNonRetryable(nil),
			wantRetryable:  false,
			wantNonRetryab: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsMarkedRetryable(tt.err); got != tt.wantRetryable {
				t.Errorf("IsMarkedRetryable() = %v, want %v", got, tt.wantRetryable)
			}
			if got := IsMarkedNonRetryable(tt.err); got != tt.wantNonRetryab {
				t.Errorf("IsMarkedNonRetryable() = %v, want %v", got, tt.wantNonRetryab)
			}
		})
	}
}
