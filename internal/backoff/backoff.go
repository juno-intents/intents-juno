package backoff

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"
)

// Config controls retry behavior.
type Config struct {
	MaxAttempts int           // 0 = unlimited
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	Jitter      float64 // 0.0-1.0, fraction of delay to randomize
}

type retryableError struct {
	err error
}

func (e *retryableError) Error() string {
	if e.err == nil {
		return "retryable: <nil>"
	}
	return fmt.Sprintf("retryable: %s", e.err.Error())
}

func (e *retryableError) Unwrap() error { return e.err }

type nonRetryableError struct {
	err error
}

func (e *nonRetryableError) Error() string {
	if e.err == nil {
		return "non-retryable: <nil>"
	}
	return fmt.Sprintf("non-retryable: %s", e.err.Error())
}

func (e *nonRetryableError) Unwrap() error { return e.err }

// IsRetryable wraps an error to explicitly mark it as retryable.
func IsRetryable(err error) error {
	if err == nil {
		return nil
	}
	return &retryableError{err: err}
}

// IsNonRetryable wraps an error to explicitly mark it as non-retryable.
func IsNonRetryable(err error) error {
	if err == nil {
		return nil
	}
	return &nonRetryableError{err: err}
}

// IsMarkedRetryable returns true if the error was explicitly marked retryable.
func IsMarkedRetryable(err error) bool {
	var re *retryableError
	return errors.As(err, &re)
}

// IsMarkedNonRetryable returns true if the error was explicitly marked non-retryable.
func IsMarkedNonRetryable(err error) bool {
	var nre *nonRetryableError
	return errors.As(err, &nre)
}

// Retry calls fn until it succeeds, exhausts attempts, or ctx is cancelled.
// Returns last error if all attempts fail.
func Retry(ctx context.Context, cfg Config, fn func(ctx context.Context) error) error {
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = 100 * time.Millisecond
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 30 * time.Second
	}
	if cfg.Jitter < 0 {
		cfg.Jitter = 0
	}
	if cfg.Jitter > 1 {
		cfg.Jitter = 1
	}

	attempt := 0
	for {
		attempt++

		err := fn(ctx)
		if err == nil {
			return nil
		}

		// Non-retryable errors short-circuit immediately.
		if IsMarkedNonRetryable(err) {
			return err
		}

		// Check if max attempts exhausted.
		if cfg.MaxAttempts > 0 && attempt >= cfg.MaxAttempts {
			return err
		}

		// Check context before sleeping.
		if ctx.Err() != nil {
			return ctx.Err()
		}

		delay := computeDelay(cfg, attempt)

		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

func computeDelay(cfg Config, attempt int) time.Duration {
	delay := cfg.BaseDelay
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay > cfg.MaxDelay {
			delay = cfg.MaxDelay
			break
		}
	}
	if delay > cfg.MaxDelay {
		delay = cfg.MaxDelay
	}

	if cfg.Jitter > 0 {
		jitterRange := float64(delay) * cfg.Jitter
		jitterAmount := time.Duration(rand.Float64()*jitterRange*2 - jitterRange)
		delay += jitterAmount
		if delay < 0 {
			delay = 0
		}
	}

	return delay
}
