package alerts

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestWithdrawalBatchStateIsStuck_IncludesFinalizingAndExcludesFinalized(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state int16
		want  bool
	}{
		{name: "planned", state: 1, want: true},
		{name: "juno_confirmed", state: 5, want: true},
		{name: "confirmed", state: 6, want: true},
		{name: "finalizing", state: 7, want: true},
		{name: "finalized", state: 8, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := withdrawalBatchStateIsStuck(tt.state); got != tt.want {
				t.Fatalf("withdrawalBatchStateIsStuck(%d) = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

func TestEngineConfigGasBalanceAddressesPrefersBaseRelayers(t *testing.T) {
	t.Parallel()

	operator := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	relayer := common.HexToAddress("0x00000000000000000000000000000000000000bb")

	cfg := EngineConfig{
		OperatorAddresses:          []common.Address{operator},
		BaseRelayerSignerAddresses: []common.Address{relayer},
	}

	got := cfg.gasBalanceAddresses()
	if len(got) != 1 || got[0] != relayer {
		t.Fatalf("gasBalanceAddresses() = %v, want [%s]", got, relayer.Hex())
	}
}

func TestEngineConfigGasBalanceAddressesFallsBackToOperators(t *testing.T) {
	t.Parallel()

	operator := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	cfg := EngineConfig{OperatorAddresses: []common.Address{operator}}

	got := cfg.gasBalanceAddresses()
	if len(got) != 1 || got[0] != operator {
		t.Fatalf("gasBalanceAddresses() = %v, want [%s]", got, operator.Hex())
	}
}

func TestEngineConfigDefaultsUseFourHourStuckBatchThreshold(t *testing.T) {
	t.Parallel()

	cfg := EngineConfig{}
	cfg.setDefaults()

	if cfg.StuckBatchMinutes != 240 {
		t.Fatalf("StuckBatchMinutes = %d, want 240", cfg.StuckBatchMinutes)
	}
}
