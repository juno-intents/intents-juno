package emf

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestEmitterEmitWritesEmbeddedMetricFormat(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	now := time.Unix(1_700_000_000, 0).UTC()

	emitter, err := New(Config{
		Namespace: OperationsNamespace,
		Writer:    &buf,
		Now:       func() time.Time { return now },
		Fields: map[string]any{
			"service": "withdraw-coordinator",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := emitter.Emit(
		Metric{Name: "WithdrawalDLQDepth", Unit: UnitCount, Value: 2},
		Metric{Name: "MarkPaidCircuitOpen", Unit: UnitNone, Value: 1},
	); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if got := payload["service"]; got != "withdraw-coordinator" {
		t.Fatalf("service field = %v, want %q", got, "withdraw-coordinator")
	}
	if got := payload["WithdrawalDLQDepth"]; got != float64(2) {
		t.Fatalf("WithdrawalDLQDepth = %v, want %v", got, float64(2))
	}
	if got := payload["MarkPaidCircuitOpen"]; got != float64(1) {
		t.Fatalf("MarkPaidCircuitOpen = %v, want %v", got, float64(1))
	}

	awsPayload, ok := payload["_aws"].(map[string]any)
	if !ok {
		t.Fatalf("_aws type = %T, want object", payload["_aws"])
	}
	if got := awsPayload["Timestamp"]; got != float64(now.UnixMilli()) {
		t.Fatalf("timestamp = %v, want %v", got, float64(now.UnixMilli()))
	}

	metrics, ok := awsPayload["CloudWatchMetrics"].([]any)
	if !ok || len(metrics) != 1 {
		t.Fatalf("CloudWatchMetrics = %#v, want single entry", awsPayload["CloudWatchMetrics"])
	}
	entry, ok := metrics[0].(map[string]any)
	if !ok {
		t.Fatalf("metric entry type = %T, want object", metrics[0])
	}
	if got := entry["Namespace"]; got != OperationsNamespace {
		t.Fatalf("namespace = %v, want %q", got, OperationsNamespace)
	}
}

func TestEmitterRejectsEmptyMetricName(t *testing.T) {
	t.Parallel()

	emitter, err := New(Config{
		Namespace: OperationsNamespace,
		Writer:    &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := emitter.Emit(Metric{Unit: UnitCount, Value: 1}); err == nil {
		t.Fatalf("expected empty metric name error")
	}
}
