package main

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/deposit"
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

func TestParseDepositSourceEvent(t *testing.T) {
	t.Parallel()

	chainID := uint64(84532)
	logIndex := uint64(3)

	tests := []struct {
		name    string
		msg     depositEventV2
		want    *deposit.SourceEvent
		wantErr bool
	}{
		{
			name: "legacy payload without source event",
			msg:  depositEventV2{},
			want: nil,
		},
		{
			name: "complete source event",
			msg: depositEventV2{
				ChainID:  &chainID,
				TxHash:   common.HexToHash("0x01").Hex(),
				LogIndex: &logIndex,
			},
			want: &deposit.SourceEvent{
				ChainID:  chainID,
				TxHash:   [32]byte(common.HexToHash("0x01")),
				LogIndex: logIndex,
			},
		},
		{
			name: "partial source event rejected",
			msg: depositEventV2{
				ChainID: &chainID,
				TxHash:  common.HexToHash("0x01").Hex(),
			},
			wantErr: true,
		},
		{
			name: "invalid tx hash rejected",
			msg: depositEventV2{
				ChainID:  &chainID,
				TxHash:   "0x1234",
				LogIndex: &logIndex,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseDepositSourceEvent(tc.msg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDepositSourceEvent: %v", err)
			}
			switch {
			case got == nil && tc.want == nil:
			case got == nil || tc.want == nil:
				t.Fatalf("source event mismatch: got=%v want=%v", got, tc.want)
			case *got != *tc.want:
				t.Fatalf("source event mismatch: got=%+v want=%+v", *got, *tc.want)
			}
		})
	}
}
