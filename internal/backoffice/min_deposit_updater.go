package backoffice

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	ethutil "github.com/juno-intents/intents-juno/internal/eth"
)

type MinDepositTxUpdater struct {
	relayer *ethutil.Relayer
	bridge  common.Address
	gasLimit uint64
}

func NewMinDepositTxUpdater(
	ctx context.Context,
	client *ethclient.Client,
	bridge common.Address,
	signer ethutil.Signer,
	gasLimit uint64,
) (*MinDepositTxUpdater, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: nil base client", ErrInvalidSettingsConfig)
	}
	if bridge == (common.Address{}) {
		return nil, fmt.Errorf("%w: nil bridge address", ErrInvalidSettingsConfig)
	}
	if signer == nil {
		return nil, fmt.Errorf("%w: nil signer", ErrInvalidSettingsConfig)
	}
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("backoffice: load chain id: %w", err)
	}
	relayer, err := ethutil.NewRelayer(client, []ethutil.Signer{signer}, ethutil.RelayerConfig{
		ChainID:               chainID,
		GasLimitMultiplier:    1.2,
		MinTipCap:             big.NewInt(1),
		ReceiptPollInterval:   2 * time.Second,
		ReplaceAfter:          15 * time.Second,
		MaxReplacements:       3,
		ReplacementBumpPercent: 20,
		MinReplacementTipBump: big.NewInt(1),
		MinReplacementFeeBump: big.NewInt(1),
	})
	if err != nil {
		return nil, fmt.Errorf("backoffice: init min deposit relayer: %w", err)
	}
	return &MinDepositTxUpdater{
		relayer: relayer,
		bridge:  bridge,
		gasLimit: gasLimit,
	}, nil
}

func (u *MinDepositTxUpdater) SetMinDepositAmount(ctx context.Context, amount uint64) (common.Hash, error) {
	if u == nil || u.relayer == nil {
		return common.Hash{}, fmt.Errorf("%w: nil min deposit updater", ErrInvalidSettingsConfig)
	}
	data, err := bridgeabi.PackSetMinDepositAmountCalldata(amount)
	if err != nil {
		return common.Hash{}, err
	}
	result, err := u.relayer.SendAndWaitMined(ctx, ethutil.TxRequest{
		To:       u.bridge,
		Data:     data,
		GasLimit: u.gasLimit,
	})
	if err != nil {
		return common.Hash{}, err
	}
	if result.Receipt == nil {
		return common.Hash{}, fmt.Errorf("backoffice: missing receipt for min deposit update")
	}
	if result.Receipt.Status == 0 {
		if result.RevertReason != "" {
			return common.Hash{}, fmt.Errorf("backoffice: min deposit update reverted: %s", result.RevertReason)
		}
		return common.Hash{}, fmt.Errorf("backoffice: min deposit update reverted")
	}
	return result.TxHash, nil
}
