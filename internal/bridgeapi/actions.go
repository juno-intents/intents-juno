package bridgeapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/depositevent"
	"github.com/juno-intents/intents-juno/internal/withdrawrequest"
)

var ErrActionUnavailable = errors.New("bridgeapi: action unavailable")

type DepositSubmitInput struct {
	BaseRecipient    common.Address
	Amount           uint64
	Nonce            uint64
	ProofWitnessItem []byte
}

type WithdrawalRequestInput struct {
	Amount      uint64
	RecipientUA []byte
}

type ActionService interface {
	SubmitDeposit(ctx context.Context, req DepositSubmitInput) (depositevent.Payload, error)
	RequestWithdrawal(ctx context.Context, req WithdrawalRequestInput) (withdrawrequest.Payload, error)
}

type queuePublisher interface {
	Publish(ctx context.Context, topic string, payload []byte) error
}

type QueueActionServiceConfig struct {
	BaseChainID       uint32
	BridgeAddr        common.Address
	DepositTopic      string
	WithdrawTopic     string
	Producer          queuePublisher
	WithdrawCfg       withdrawrequest.Config
	RequestWithdrawFn func(context.Context, withdrawrequest.Config, withdrawrequest.Request) (withdrawrequest.Payload, error)
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
	if strings.TrimSpace(cfg.WithdrawTopic) == "" {
		return nil, errors.New("withdraw topic is required")
	}
	if cfg.Producer == nil {
		return nil, errors.New("producer is required")
	}
	if cfg.RequestWithdrawFn == nil {
		cfg.RequestWithdrawFn = withdrawrequest.RequestWithdrawal
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

func (s *QueueActionService) RequestWithdrawal(ctx context.Context, req WithdrawalRequestInput) (withdrawrequest.Payload, error) {
	if req.Amount == 0 {
		return withdrawrequest.Payload{}, errors.New("amount must be > 0")
	}
	if len(req.RecipientUA) == 0 {
		return withdrawrequest.Payload{}, errors.New("recipient ua is required")
	}

	payload, err := s.cfg.RequestWithdrawFn(ctx, s.cfg.WithdrawCfg, withdrawrequest.Request{
		Amount:      req.Amount,
		RecipientUA: req.RecipientUA,
	})
	if err != nil {
		return withdrawrequest.Payload{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return withdrawrequest.Payload{}, fmt.Errorf("marshal withdraw payload: %w", err)
	}
	if err := s.cfg.Producer.Publish(ctx, s.cfg.WithdrawTopic, encoded); err != nil {
		return withdrawrequest.Payload{}, fmt.Errorf("publish withdraw payload: %w", err)
	}
	return payload, nil
}
