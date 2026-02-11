package proofclient

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/queue"
)

var (
	ErrInvalidConfig = errors.New("proofclient: invalid config")
	ErrProofFailed   = errors.New("proofclient: proof request failed")
)

type Request struct {
	JobID        common.Hash
	Pipeline     string
	ImageID      common.Hash
	Journal      []byte
	PrivateInput []byte
	Deadline     time.Time
	Priority     int
}

type Result struct {
	Seal     []byte
	Metadata map[string]string
}

type Client interface {
	RequestProof(ctx context.Context, req Request) (Result, error)
}

type FailureError struct {
	Code      string
	Retryable bool
	Message   string
}

func (e *FailureError) Error() string {
	if e == nil {
		return ""
	}
	if strings.TrimSpace(e.Code) == "" && strings.TrimSpace(e.Message) == "" {
		return ErrProofFailed.Error()
	}
	if strings.TrimSpace(e.Code) == "" {
		return e.Message
	}
	if strings.TrimSpace(e.Message) == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

func (e *FailureError) Unwrap() error {
	return ErrProofFailed
}

type QueueConfig struct {
	RequestTopic string
	ResultTopic  string
	FailureTopic string

	Producer queue.Producer
	Consumer queue.Consumer

	AckTimeout      time.Duration
	DefaultDeadline time.Duration

	Log *slog.Logger
}

type QueueClient struct {
	cfg QueueConfig
}

func NewQueueClient(cfg QueueConfig) (*QueueClient, error) {
	if cfg.Producer == nil || cfg.Consumer == nil {
		return nil, fmt.Errorf("%w: producer and consumer are required", ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.RequestTopic) == "" || strings.TrimSpace(cfg.ResultTopic) == "" || strings.TrimSpace(cfg.FailureTopic) == "" {
		return nil, fmt.Errorf("%w: request/result/failure topics are required", ErrInvalidConfig)
	}
	if cfg.AckTimeout <= 0 {
		cfg.AckTimeout = 5 * time.Second
	}
	if cfg.DefaultDeadline <= 0 {
		cfg.DefaultDeadline = 15 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return &QueueClient{cfg: cfg}, nil
}

func (c *QueueClient) RequestProof(ctx context.Context, req Request) (Result, error) {
	if err := validateRequest(req); err != nil {
		return Result{}, err
	}

	deadline := req.Deadline.UTC()
	if deadline.IsZero() {
		deadline = time.Now().UTC().Add(c.cfg.DefaultDeadline)
	}
	payload, err := json.Marshal(map[string]any{
		"job_id":        req.JobID.Hex(),
		"pipeline":      strings.TrimSpace(req.Pipeline),
		"image_id":      req.ImageID.Hex(),
		"journal":       "0x" + hex.EncodeToString(req.Journal),
		"private_input": "0x" + hex.EncodeToString(req.PrivateInput),
		"deadline":      deadline.Format(time.RFC3339),
		"priority":      req.Priority,
	})
	if err != nil {
		return Result{}, fmt.Errorf("proofclient: marshal request payload: %w", err)
	}
	if err := c.cfg.Producer.Publish(ctx, c.cfg.RequestTopic, payload); err != nil {
		return Result{}, fmt.Errorf("proofclient: publish request: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case err, ok := <-c.cfg.Consumer.Errors():
			if !ok {
				continue
			}
			if err != nil {
				return Result{}, fmt.Errorf("proofclient: consume error: %w", err)
			}
		case msg, ok := <-c.cfg.Consumer.Messages():
			if !ok {
				return Result{}, fmt.Errorf("proofclient: response consumer closed")
			}
			result, matched, err := c.handleResponseMessage(msg, req.JobID)
			c.ack(msg)
			if err != nil {
				return Result{}, err
			}
			if matched {
				return result, nil
			}
		}
	}
}

func (c *QueueClient) handleResponseMessage(msg queue.Message, jobID common.Hash) (Result, bool, error) {
	if strings.TrimSpace(string(msg.Value)) == "" {
		return Result{}, false, nil
	}
	var env struct {
		Version string `json:"version"`
		JobID   string `json:"job_id"`
	}
	if err := json.Unmarshal(msg.Value, &env); err != nil {
		c.cfg.Log.Warn("proofclient: ignore invalid response payload", "err", err)
		return Result{}, false, nil
	}
	gotJobID := common.HexToHash(strings.TrimSpace(env.JobID))
	if gotJobID != jobID {
		return Result{}, false, nil
	}

	switch strings.TrimSpace(env.Version) {
	case "proof.fulfillment.v1":
		var res struct {
			Seal     string            `json:"seal"`
			Metadata map[string]string `json:"metadata"`
		}
		if err := json.Unmarshal(msg.Value, &res); err != nil {
			return Result{}, true, fmt.Errorf("proofclient: decode fulfillment: %w", err)
		}
		seal, err := decodeHex(res.Seal)
		if err != nil {
			return Result{}, true, fmt.Errorf("proofclient: decode fulfillment seal: %w", err)
		}
		return Result{
			Seal:     seal,
			Metadata: cloneMap(res.Metadata),
		}, true, nil
	case "proof.failure.v1":
		var fail struct {
			ErrorCode string `json:"error_code"`
			Retryable bool   `json:"retryable"`
			Message   string `json:"message"`
		}
		if err := json.Unmarshal(msg.Value, &fail); err != nil {
			return Result{}, true, fmt.Errorf("proofclient: decode failure: %w", err)
		}
		return Result{}, true, &FailureError{
			Code:      strings.TrimSpace(fail.ErrorCode),
			Retryable: fail.Retryable,
			Message:   strings.TrimSpace(fail.Message),
		}
	default:
		c.cfg.Log.Warn("proofclient: ignore unknown response version", "version", env.Version)
		return Result{}, false, nil
	}
}

func (c *QueueClient) ack(msg queue.Message) {
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.AckTimeout)
	defer cancel()
	if err := msg.Ack(ctx); err != nil && !errors.Is(err, context.Canceled) {
		c.cfg.Log.Warn("proofclient: ack failed", "err", err)
	}
}

type StaticClient struct {
	Result Result
	Err    error
}

func (c *StaticClient) RequestProof(_ context.Context, req Request) (Result, error) {
	if err := validateRequest(req); err != nil {
		return Result{}, err
	}
	if c == nil {
		return Result{}, fmt.Errorf("%w: nil static client", ErrInvalidConfig)
	}
	if c.Err != nil {
		return Result{}, c.Err
	}
	return Result{
		Seal:     append([]byte(nil), c.Result.Seal...),
		Metadata: cloneMap(c.Result.Metadata),
	}, nil
}

func validateRequest(req Request) error {
	if req.JobID == (common.Hash{}) {
		return fmt.Errorf("%w: missing job id", ErrInvalidConfig)
	}
	if strings.TrimSpace(req.Pipeline) == "" {
		return fmt.Errorf("%w: missing pipeline", ErrInvalidConfig)
	}
	if req.ImageID == (common.Hash{}) {
		return fmt.Errorf("%w: missing image id", ErrInvalidConfig)
	}
	if len(req.Journal) == 0 {
		return fmt.Errorf("%w: empty journal", ErrInvalidConfig)
	}
	if req.Priority < 0 {
		return fmt.Errorf("%w: priority must be >= 0", ErrInvalidConfig)
	}
	return nil
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func decodeHex(v string) ([]byte, error) {
	s := strings.TrimSpace(strings.TrimPrefix(v, "0x"))
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}
