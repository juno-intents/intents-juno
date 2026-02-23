package prooffunder

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/leases"
	sp1 "github.com/juno-intents/intents-juno/internal/sp1network"
)

type Alerter interface {
	EmitCritical(ctx context.Context, message string, fields map[string]string) error
}

type Config struct {
	LeaseName     string
	LeaseTTL      time.Duration
	CheckInterval time.Duration

	RequestorAddress common.Address

	MinBalanceWei      *big.Int
	CriticalBalanceWei *big.Int
}

type Service struct {
	cfg     Config
	ownerID string
	leases  leases.Store
	funding sp1.FundingClient
	alerter Alerter
	log     *slog.Logger
}

func New(cfg Config, ownerID string, leaseStore leases.Store, funding sp1.FundingClient, alerter Alerter) (*Service, error) {
	if leaseStore == nil || funding == nil {
		return nil, fmt.Errorf("prooffunder: nil dependency")
	}
	if ownerID == "" {
		return nil, fmt.Errorf("prooffunder: owner id is required")
	}
	if cfg.LeaseTTL <= 0 || cfg.CheckInterval <= 0 {
		return nil, fmt.Errorf("prooffunder: lease/check interval must be > 0")
	}
	if cfg.LeaseName == "" {
		cfg.LeaseName = "proof-funder"
	}
	if cfg.RequestorAddress == (common.Address{}) {
		return nil, fmt.Errorf("prooffunder: requestor address required")
	}
	if !isPositive(cfg.MinBalanceWei) || !isPositive(cfg.CriticalBalanceWei) {
		return nil, fmt.Errorf("prooffunder: balances must be positive")
	}
	if cfg.CriticalBalanceWei.Cmp(cfg.MinBalanceWei) > 0 {
		return nil, fmt.Errorf("prooffunder: critical balance must be <= min balance")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return &Service{
		cfg:     cfg,
		ownerID: ownerID,
		leases:  leaseStore,
		funding: funding,
		alerter: alerter,
		log:     log,
	}, nil
}

func (s *Service) WithLogger(log *slog.Logger) *Service {
	if s == nil {
		return s
	}
	if log != nil {
		s.log = log
	}
	return s
}

func (s *Service) Tick(ctx context.Context) error {
	if s == nil || s.leases == nil || s.funding == nil {
		return fmt.Errorf("prooffunder: nil service")
	}
	leader, err := s.tickLeadership(ctx)
	if err != nil {
		return err
	}
	if !leader {
		return nil
	}

	balance, err := s.funding.RequestorBalanceWei(ctx, s.cfg.RequestorAddress)
	if err != nil {
		return err
	}
	s.log.Info("proof-funder metrics",
		"requestor_address", s.cfg.RequestorAddress,
		"requestor_balance_wei", balance.String(),
	)

	if balance.Cmp(s.cfg.CriticalBalanceWei) < 0 {
		s.log.Error("critical requestor balance", "requestor", s.cfg.RequestorAddress, "balance_wei", balance.String(), "critical_wei", s.cfg.CriticalBalanceWei.String())
		if s.alerter != nil {
			_ = s.alerter.EmitCritical(ctx, "proof requestor balance below critical threshold", map[string]string{
				"requestor_address": s.cfg.RequestorAddress.Hex(),
				"balance_wei":       balance.String(),
				"critical_wei":      s.cfg.CriticalBalanceWei.String(),
			})
		}
	}

	if balance.Cmp(s.cfg.MinBalanceWei) < 0 {
		required := new(big.Int).Sub(s.cfg.MinBalanceWei, balance)
		return fmt.Errorf(
			"prooffunder: insufficient requestor balance: have=%s min=%s refill_wei=%s",
			balance.String(),
			s.cfg.MinBalanceWei.String(),
			required.String(),
		)
	}
	return nil
}

func (s *Service) tickLeadership(ctx context.Context) (bool, error) {
	if _, ok, err := s.leases.Renew(ctx, s.cfg.LeaseName, s.ownerID, s.cfg.LeaseTTL); err == nil && ok {
		return true, nil
	}
	_, ok, err := s.leases.TryAcquire(ctx, s.cfg.LeaseName, s.ownerID, s.cfg.LeaseTTL)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func isPositive(v *big.Int) bool {
	return v != nil && v.Sign() > 0
}
