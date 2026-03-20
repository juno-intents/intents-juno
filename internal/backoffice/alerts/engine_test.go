package alerts

import "testing"

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
