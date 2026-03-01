package e2eorch

import (
	"context"
	"fmt"
	"log"
	"time"
)

// PollFunc is called repeatedly by PollUntil. It returns:
//   - done: true when the desired terminal state is reached.
//   - description: short human-readable label for the current state (logged on transition).
//   - err: non-nil only for hard failures that should abort polling immediately.
type PollFunc func(ctx context.Context) (done bool, description string, err error)

// PollUntil repeatedly calls fn at the given interval until fn reports done,
// the timeout expires, or the context is cancelled. It logs every state
// transition (when description changes between calls).
//
// Returns nil on success (fn returned done=true), or an error describing
// the timeout / cancellation / hard failure.
func PollUntil(ctx context.Context, timeout, interval time.Duration, fn PollFunc) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastDesc string

	// Run once immediately before the first tick.
	done, desc, err := fn(ctx)
	if err != nil {
		return fmt.Errorf("poll: initial call failed: %w", err)
	}
	if desc != lastDesc {
		log.Printf("[poll] state: %s", desc)
		lastDesc = desc
	}
	if done {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("poll: timed out after %s (last state: %s): %w", timeout, lastDesc, ctx.Err())
		case <-ticker.C:
			done, desc, err = fn(ctx)
			if err != nil {
				return fmt.Errorf("poll: hard failure (state: %s): %w", lastDesc, err)
			}
			if desc != lastDesc {
				log.Printf("[poll] state: %s -> %s", lastDesc, desc)
				lastDesc = desc
			}
			if done {
				log.Printf("[poll] done (%s)", desc)
				return nil
			}
		}
	}
}
