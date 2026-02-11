package prooffunder

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/boundless"
	"github.com/juno-intents/intents-juno/internal/leases"
)

type Alerter interface {
	EmitCritical(ctx context.Context, message string, fields map[string]string) error
}

type Config struct {
	LeaseName     string
	LeaseTTL      time.Duration
	CheckInterval time.Duration

	OwnerAddress     common.Address
	RequestorAddress common.Address

	MinBalanceWei      *big.Int
	TargetBalanceWei   *big.Int
	CriticalBalanceWei *big.Int
	MaxTopUpPerTxWei   *big.Int
}

type Service struct {
	cfg      Config
	ownerID  string
	leases   leases.Store
	funding  boundless.FundingClient
	alerter  Alerter
	log      *slog.Logger
}

func New(cfg Config, ownerID string, leaseStore leases.Store, funding boundless.FundingClient, alerter Alerter) (*Service, error) {
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
	if cfg.OwnerAddress == (common.Address{}) || cfg.RequestorAddress == (common.Address{}) {
		return nil, fmt.Errorf("prooffunder: owner/requestor addresses required")
	}
	if !isPositive(cfg.MinBalanceWei) || !isPositive(cfg.TargetBalanceWei) || !isPositive(cfg.CriticalBalanceWei) || !isPositive(cfg.MaxTopUpPerTxWei) {
		return nil, fmt.Errorf("prooffunder: balances must be positive")
	}
	if cfg.TargetBalanceWei.Cmp(cfg.MinBalanceWei) < 0 {
		return nil, fmt.Errorf("prooffunder: target balance must be >= min balance")
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

func ComputeTopUpAmount(balanceWei, minBalanceWei, targetBalanceWei, maxTopUpPerTxWei *big.Int) (*big.Int, bool) {
	if balanceWei == nil || minBalanceWei == nil || targetBalanceWei == nil || maxTopUpPerTxWei == nil {
		return big.NewInt(0), false
	}
	if balanceWei.Cmp(minBalanceWei) >= 0 {
		return big.NewInt(0), false
	}
	amount := new(big.Int).Sub(targetBalanceWei, balanceWei)
	if amount.Sign() <= 0 {
		return big.NewInt(0), false
	}
	if amount.Cmp(maxTopUpPerTxWei) > 0 {
		amount = new(big.Int).Set(maxTopUpPerTxWei)
	}
	if amount.Sign() <= 0 {
		return big.NewInt(0), false
	}
	return amount, true
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

	topupAmount, shouldTopUp := ComputeTopUpAmount(balance, s.cfg.MinBalanceWei, s.cfg.TargetBalanceWei, s.cfg.MaxTopUpPerTxWei)
	if !shouldTopUp {
		return nil
	}

	txHash, err := s.funding.TopUpRequestor(ctx, s.cfg.RequestorAddress, topupAmount)
	if err != nil {
		return err
	}
	s.log.Info("requestor topup submitted", "requestor", s.cfg.RequestorAddress, "amount_wei", topupAmount.String(), "tx_hash", txHash)
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

