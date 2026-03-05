package bridgeapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/depositevent"
)

var ErrActionUnavailable = errors.New("bridgeapi: action unavailable")

type DepositSubmitInput struct {
	BaseRecipient    common.Address
	Amount           uint64
	Nonce            uint64
	ProofWitnessItem []byte
}

type ActionService interface {
	SubmitDeposit(ctx context.Context, req DepositSubmitInput) (depositevent.Payload, error)
}

type queuePublisher interface {
	Publish(ctx context.Context, topic string, payload []byte) error
}

type QueueActionServiceConfig struct {
	BaseChainID  uint32
	BridgeAddr   common.Address
	DepositTopic string
	Producer     queuePublisher
}

type QueueActionService struct {
	cfg QueueActionServiceConfig
}

func NewQueueActionService(cfg QueueActionServiceConfig) (*QueueActionService, error) {
	if cfg.BaseChainID == 0 {
		return nil, errors.New("base chain id is required")
	}
	if cfg.BridgeAddr == (common.Address{}) {
		return nil, errors.New("bridge address is required")
	}
	if strings.TrimSpace(cfg.DepositTopic) == "" {
		return nil, errors.New("deposit topic is required")
	}
	if cfg.Producer == nil {
		return nil, errors.New("producer is required")
	}
	return &QueueActionService{cfg: cfg}, nil
}

func (s *QueueActionService) SubmitDeposit(ctx context.Context, req DepositSubmitInput) (depositevent.Payload, error) {
	if req.BaseRecipient == (common.Address{}) {
		return depositevent.Payload{}, errors.New("base recipient is required")
	}
	if req.Amount == 0 {
		return depositevent.Payload{}, errors.New("amount must be > 0")
	}
	if len(req.ProofWitnessItem) == 0 {
		return depositevent.Payload{}, errors.New("proof witness item is required")
	}

	payload, err := depositevent.BuildPayload(
		s.cfg.BaseChainID,
		s.cfg.BridgeAddr,
		req.BaseRecipient,
		req.Amount,
		req.Nonce,
		req.ProofWitnessItem,
	)
	if err != nil {
		return depositevent.Payload{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return depositevent.Payload{}, fmt.Errorf("marshal deposit payload: %w", err)
	}
	if err := s.cfg.Producer.Publish(ctx, s.cfg.DepositTopic, encoded); err != nil {
		return depositevent.Payload{}, fmt.Errorf("publish deposit payload: %w", err)
	}
	return payload, nil
}

