package proofrequestor

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/juno-intents/intents-juno/internal/emf"
)

type proofMetricCapture struct {
	calls [][]emf.Metric
}

func (m *proofMetricCapture) Emit(metrics ...emf.Metric) error {
	cloned := append([]emf.Metric(nil), metrics...)
	m.calls = append(m.calls, cloned)
	return nil
}

func TestWorkerEmitMetricsIncludesOutcomeCounts(t *testing.T) {
	t.Parallel()

	capture := &proofMetricCapture{}
	worker := &Worker{
		cfg: WorkerConfig{
			MetricsEmitter: capture,
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	worker.emitMetrics(time.Now().Add(-2*time.Second), true, true, 1500*time.Millisecond)

	if len(capture.calls) != 1 {
		t.Fatalf("metric calls = %d, want 1", len(capture.calls))
	}
	got := map[string]float64{}
	for _, metric := range capture.calls[0] {
		got[metric.Name] = metric.Value
	}
	if got["ProofRequestSuccessCount"] != 1 {
		t.Fatalf("ProofRequestSuccessCount = %v, want 1", got["ProofRequestSuccessCount"])
	}
	if got["ProofRequestFailureCount"] != 0 {
		t.Fatalf("ProofRequestFailureCount = %v, want 0", got["ProofRequestFailureCount"])
	}
	if got["ProofRequestLatencyMs"] != 1500 {
		t.Fatalf("ProofRequestLatencyMs = %v, want 1500", got["ProofRequestLatencyMs"])
	}
}
