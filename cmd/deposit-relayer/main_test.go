package main

import (
	"errors"
	"testing"

	"github.com/juno-intents/intents-juno/internal/depositrelayer"
)

func TestIsCheckpointPermanentError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "invalid checkpoint", err: depositrelayer.ErrInvalidCheckpoint, want: true},
		{name: "wrapped invalid checkpoint", err: errors.New("wrap: " + depositrelayer.ErrInvalidCheckpoint.Error()), want: false},
		{name: "transient", err: errors.New("temporary queue outage"), want: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isCheckpointPermanentError(tc.err); got != tc.want {
				t.Fatalf("isCheckpointPermanentError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
