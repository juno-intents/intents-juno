package proofrequestor

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/dlq"
	"github.com/juno-intents/intents-juno/internal/emf"
	"github.com/juno-intents/intents-juno/internal/proof"
	"github.com/juno-intents/intents-juno/internal/queue"
)

// DefaultMaxDLQAttempts is the default max attempts before a retryable failure is sent to the DLQ.
const DefaultMaxDLQAttempts = 3

type WorkerConfig struct {
	InputTopic   string
	ResultTopic  string
	FailureTopic string

	MaxInflight int
	AckTimeout  time.Duration

	// DLQStore is an optional dead-letter queue store. If nil, DLQ insertion is skipped.
	DLQStore dlq.Store
	// MaxDLQAttempts is the max number of attempts before a retryable failure is sent to the DLQ.
	// Defaults to DefaultMaxDLQAttempts if zero.
	MaxDLQAttempts int

	MetricsEmitter metricEmitter
}

type metricEmitter interface {
	Emit(...emf.Metric) error
}

type Worker struct {
	cfg WorkerConfig

	service  *Service
	consumer queue.Consumer
	producer queue.Producer
	log      *slog.Logger

	inflight      atomic.Int64
	successCount  atomic.Uint64
	failureCount  atomic.Uint64
	fallbackCount atomic.Uint64
}

func NewWorker(cfg WorkerConfig, service *Service, consumer queue.Consumer, producer queue.Producer, log *slog.Logger) (*Worker, error) {
	if service == nil || consumer == nil || producer == nil {
		return nil, fmt.Errorf("%w: nil dependency", proof.ErrInvalidConfig)
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = 1
	}
	if cfg.AckTimeout <= 0 {
		cfg.AckTimeout = 5 * time.Second
	}
	if cfg.InputTopic == "" || cfg.ResultTopic == "" || cfg.FailureTopic == "" {
		return nil, fmt.Errorf("%w: input/result/failure topics are required", proof.ErrInvalidConfig)
	}
	if cfg.MaxDLQAttempts <= 0 {
		cfg.MaxDLQAttempts = DefaultMaxDLQAttempts
	}
	if log == nil {
		log = slog.Default()
	}
	return &Worker{
		cfg:      cfg,
		service:  service,
		consumer: consumer,
		producer: producer,
		log:      log,
	}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	sem := make(chan struct{}, w.cfg.MaxInflight)
	var wg sync.WaitGroup

	msgCh := w.consumer.Messages()
	errCh := w.consumer.Errors()

	var firstErr error
	var firstErrMu sync.Mutex
	setFirstErr := func(err error) {
		if err == nil {
			return
		}
		firstErrMu.Lock()
		defer firstErrMu.Unlock()
		if firstErr == nil {
			firstErr = err
		}
	}

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return firstErr
		case err, ok := <-errCh:
			if !ok {
				errCh = nil
				continue
			}
			if err != nil {
				w.log.Error("proof-requestor queue consume error", "err", err)
				setFirstErr(err)
			}
		case msg, ok := <-msgCh:
			if !ok {
				wg.Wait()
				return firstErr
			}
			sem <- struct{}{}
			wg.Add(1)
			go func(qmsg queue.Message) {
				defer wg.Done()
				defer func() { <-sem }()

				w.inflight.Add(1)
				defer w.inflight.Add(-1)
				if err := w.handleMessage(ctx, qmsg); err != nil {
					setFirstErr(err)
					w.log.Error("proof-requestor handle message", "err", err)
				}
			}(msg)
		}
	}
}

func (w *Worker) handleMessage(ctx context.Context, msg queue.Message) error {
	startedAt := time.Now()

	job, err := proof.DecodeJobRequest(msg.Value)
	if err != nil {
		w.maybeDLQMalformedRequest(ctx, msg, err)
		failPayload, ferr := proof.EncodeFailureMessage(proof.FailureMessage{
			JobID:     common.Hash{},
			ErrorCode: "invalid_payload",
			Retryable: false,
			Message:   err.Error(),
		})
		if ferr == nil {
			_ = w.producer.Publish(ctx, w.cfg.FailureTopic, failPayload)
		}
		w.failureCount.Add(1)
		w.emitMetrics(msg.Timestamp, false, false, time.Since(startedAt))
		ackMessage(msg, w.cfg.AckTimeout, w.log)
		return nil
	}

	out, err := w.service.ProcessJob(ctx, job)
	if err != nil {
		if errors.Is(err, proof.ErrJobMismatch) {
			w.log.Warn(
				"proof-requestor ignoring mismatched duplicate payload",
				"job_id", job.JobID.Hex(),
				"err", err,
			)
			ackMessage(msg, w.cfg.AckTimeout, w.log)
			return nil
		}
		failPayload, ferr := proof.EncodeFailureMessage(proof.FailureMessage{
			JobID:     job.JobID,
			ErrorCode: "requestor_internal_error",
			Retryable: true,
			Message:   err.Error(),
		})
		if ferr != nil {
			return ferr
		}
		if perr := w.producer.Publish(ctx, w.cfg.FailureTopic, failPayload); perr != nil {
			return perr
		}
		w.failureCount.Add(1)
		w.emitMetrics(msg.Timestamp, false, false, time.Since(startedAt))
		ackMessage(msg, w.cfg.AckTimeout, w.log)
		return nil
	}

	switch out.Status {
	case StatusFulfilled:
		payload, err := proof.EncodeFulfillmentMessage(proof.FulfillmentMessage{
			JobID:          job.JobID,
			RequestID:      out.RequestID,
			Seal:           out.Seal,
			Journal:        job.Journal,
			Metadata:       out.Metadata,
			SubmissionPath: out.SubmissionPath,
		})
		if err != nil {
			return err
		}
		if err := w.producer.Publish(ctx, w.cfg.ResultTopic, payload); err != nil {
			return err
		}
		if out.FallbackUsed {
			w.fallbackCount.Add(1)
		}
		w.successCount.Add(1)
		w.emitMetrics(msg.Timestamp, true, out.FallbackUsed, time.Since(startedAt))
	case StatusFailed:
		w.log.Error(
			"proof-requestor submission failed",
			"job_id", job.JobID.Hex(),
			"request_id", out.RequestID,
			"error_code", out.ErrorCode,
			"retryable", out.Retryable,
			"message", out.ErrorMessage,
			"attempt_count", out.AttemptCount,
		)
		payload, err := proof.EncodeFailureMessage(proof.FailureMessage{
			JobID:     job.JobID,
			RequestID: out.RequestID,
			ErrorCode: out.ErrorCode,
			Retryable: out.Retryable,
			Message:   out.ErrorMessage,
		})
		if err != nil {
			return err
		}
		if err := w.producer.Publish(ctx, w.cfg.FailureTopic, payload); err != nil {
			return err
		}
		w.failureCount.Add(1)
		w.emitMetrics(msg.Timestamp, false, false, time.Since(startedAt))

		// Insert into DLQ on terminal failure or when max attempts exceeded.
		shouldDLQ := !out.Retryable || out.AttemptCount >= w.cfg.MaxDLQAttempts
		if shouldDLQ {
			w.maybeDLQProof(ctx, job, out)
		}
	case StatusSkipped:
		// Already handled by another worker instance or terminal state.
	}

	ackMessage(msg, w.cfg.AckTimeout, w.log)
	return nil
}

func (w *Worker) maybeDLQMalformedRequest(ctx context.Context, msg queue.Message, decodeErr error) {
	if w.cfg.DLQStore == nil {
		return
	}

	sum := sha256.Sum256([]byte(msg.Topic + "\x00" + string(msg.Value)))
	rec := dlq.ProofDLQRecord{
		JobID:        sum,
		Pipeline:     "proof-request",
		State:        4,
		ErrorCode:    "invalid_payload",
		ErrorMessage: decodeErr.Error(),
		AttemptCount: 1,
		JobPayload:   append([]byte(nil), msg.Value...),
		CreatedAt:    time.Now().UTC(),
	}
	if err := w.cfg.DLQStore.InsertProofDLQ(ctx, rec); err != nil {
		w.log.Error("proof-requestor failed to insert malformed request into DLQ", "err", err)
	}
}

// maybeDLQProof inserts a failed proof job into the dead-letter queue.
// If DLQStore is nil, this is a no-op.
func (w *Worker) maybeDLQProof(ctx context.Context, job proof.JobRequest, out Outcome) {
	if w.cfg.DLQStore == nil {
		return
	}

	rec := dlq.ProofDLQRecord{
		JobID:        [32]byte(job.JobID),
		Pipeline:     job.Pipeline,
		ImageID:      [32]byte(job.ImageID),
		State:        int16(proofStateFromOutcome(out)),
		ErrorCode:    out.ErrorCode,
		ErrorMessage: out.ErrorMessage,
		AttemptCount: out.AttemptCount,
		JobPayload:   nil, // Payload not stored by default to save space.
	}

	if err := w.cfg.DLQStore.InsertProofDLQ(ctx, rec); err != nil {
		w.log.Error("proof-requestor failed to insert into DLQ",
			"job_id", job.JobID.Hex(),
			"err", err,
		)
	} else {
		w.log.Info("proof-requestor inserted into DLQ",
			"job_id", job.JobID.Hex(),
			"error_code", out.ErrorCode,
			"attempt_count", out.AttemptCount,
		)
	}
}

// proofStateFromOutcome maps an Outcome to a proof lifecycle state int for DLQ storage.
func proofStateFromOutcome(out Outcome) int {
	if out.Retryable {
		return 3 // failed_retryable
	}
	return 4 // failed_terminal
}

func (w *Worker) emitMetrics(ts time.Time, success bool, fallback bool, latency time.Duration) {
	lagSeconds := float64(0)
	if !ts.IsZero() {
		lag := time.Since(ts)
		if lag > 0 {
			lagSeconds = lag.Seconds()
		}
	}
	if latency < 0 {
		latency = 0
	}
	latencyMs := float64(latency.Milliseconds())
	w.log.Info("proof-requestor metrics",
		"queue_lag_seconds", lagSeconds,
		"request_latency_ms", latencyMs,
		"in_flight_requests", w.inflight.Load(),
		"submission_success_count", w.successCount.Load(),
		"submission_failure_count", w.failureCount.Load(),
		"fallback_usage_count", w.fallbackCount.Load(),
		"success", success,
		"fallback", fallback,
	)
	if w.cfg.MetricsEmitter == nil {
		return
	}
	successValue := 0.0
	failureValue := 1.0
	if success {
		successValue = 1
		failureValue = 0
	}
	if err := w.cfg.MetricsEmitter.Emit(
		emf.Metric{Name: "ProofRequestSuccessCount", Unit: emf.UnitCount, Value: successValue},
		emf.Metric{Name: "ProofRequestFailureCount", Unit: emf.UnitCount, Value: failureValue},
		emf.Metric{Name: "ProofRequestLatencyMs", Unit: emf.UnitMilliseconds, Value: latencyMs},
	); err != nil {
		w.log.Warn("proof-requestor emit metrics", "err", err)
	}
}

func ackMessage(msg queue.Message, timeout time.Duration, log *slog.Logger) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := msg.Ack(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("proof-requestor ack message", "err", err)
	}
}
