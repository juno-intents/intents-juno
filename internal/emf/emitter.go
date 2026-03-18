package emf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

var ErrInvalidConfig = errors.New("emf: invalid config")

const (
	OperationsNamespace = "IntentsJuno/Operations"

	UnitCount        = "Count"
	UnitMilliseconds = "Milliseconds"
	UnitSeconds      = "Seconds"
	UnitNone         = "None"
)

type Metric struct {
	Name  string
	Unit  string
	Value float64
}

type Config struct {
	Namespace string
	Writer    io.Writer
	Now       func() time.Time
	Fields    map[string]any
}

type Emitter struct {
	namespace string
	writer    io.Writer
	now       func() time.Time
	fields    map[string]any
	mu        sync.Mutex
}

func New(cfg Config) (*Emitter, error) {
	namespace := strings.TrimSpace(cfg.Namespace)
	if namespace == "" {
		return nil, fmt.Errorf("%w: namespace is required", ErrInvalidConfig)
	}
	if cfg.Writer == nil {
		return nil, fmt.Errorf("%w: writer is required", ErrInvalidConfig)
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	fields := make(map[string]any, len(cfg.Fields))
	for key, value := range cfg.Fields {
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("%w: field key is required", ErrInvalidConfig)
		}
		fields[key] = value
	}
	return &Emitter{
		namespace: namespace,
		writer:    cfg.Writer,
		now:       nowFn,
		fields:    fields,
	}, nil
}

func (e *Emitter) Emit(metrics ...Metric) error {
	if e == nil || len(metrics) == 0 {
		return nil
	}

	metricDefs := make([]map[string]any, 0, len(metrics))
	payload := make(map[string]any, len(metrics)+len(e.fields)+1)
	for key, value := range e.fields {
		payload[key] = value
	}

	for _, metric := range metrics {
		name := strings.TrimSpace(metric.Name)
		if name == "" {
			return fmt.Errorf("%w: metric name is required", ErrInvalidConfig)
		}
		unit := strings.TrimSpace(metric.Unit)
		if unit == "" {
			unit = UnitNone
		}
		metricDefs = append(metricDefs, map[string]any{
			"Name": name,
			"Unit": unit,
		})
		payload[name] = metric.Value
	}

	payload["_aws"] = map[string]any{
		"Timestamp": e.now().UTC().UnixMilli(),
		"CloudWatchMetrics": []map[string]any{
			{
				"Namespace":  e.namespace,
				"Dimensions": [][]string{{}},
				"Metrics":    metricDefs,
			},
		},
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	return json.NewEncoder(e.writer).Encode(payload)
}
