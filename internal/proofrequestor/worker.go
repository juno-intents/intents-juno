package proofrequestor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/proof"
	"github.com/juno-intents/intents-juno/internal/queue"
)

type WorkerConfig struct {
	InputTopic   string
	ResultTopic  string
	FailureTopic string

	MaxInflight int
	AckTimeout  time.Duration
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
	job, err := proof.DecodeJobRequest(msg.Value)
	if err != nil {
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
		w.emitMetrics(msg.Timestamp, false, false)
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
		w.emitMetrics(msg.Timestamp, false, false)
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
		w.emitMetrics(msg.Timestamp, true, out.FallbackUsed)
	case StatusFailed:
		w.log.Error(
			"proof-requestor submission failed",
			"job_id", job.JobID.Hex(),
			"request_id", out.RequestID,
			"error_code", out.ErrorCode,
			"retryable", out.Retryable,
			"message", out.ErrorMessage,
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
		w.emitMetrics(msg.Timestamp, false, false)
	case StatusSkipped:
		// Already handled by another worker instance or terminal state.
	}

	ackMessage(msg, w.cfg.AckTimeout, w.log)
	return nil
}

func (w *Worker) emitMetrics(ts time.Time, success bool, fallback bool) {
	lagSeconds := float64(0)
	if !ts.IsZero() {
		lag := time.Since(ts)
		if lag > 0 {
			lagSeconds = lag.Seconds()
		}
	}
	w.log.Info("proof-requestor metrics",
		"queue_lag_seconds", lagSeconds,
		"in_flight_requests", w.inflight.Load(),
		"submission_success_count", w.successCount.Load(),
		"submission_failure_count", w.failureCount.Load(),
		"fallback_usage_count", w.fallbackCount.Load(),
		"success", success,
		"fallback", fallback,
	)
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
