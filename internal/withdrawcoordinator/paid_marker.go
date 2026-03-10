package withdrawcoordinator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
)

var ErrInvalidPaidMarkerConfig = errors.New("withdrawcoordinator: invalid paid marker config")

type BasePaidMarkerConfig struct {
	BaseChainID   uint64
	BridgeAddress common.Address
	GasLimit      uint64
}

type BasePaidMarker struct {
	cfg BasePaidMarkerConfig

	sender httpapiSender
	signer ExtendDigestSigner
}

func NewBasePaidMarker(cfg BasePaidMarkerConfig, sender httpapiSender, signer ExtendDigestSigner) (*BasePaidMarker, error) {
	if cfg.BaseChainID == 0 {
		return nil, fmt.Errorf("%w: base chain id must be non-zero", ErrInvalidPaidMarkerConfig)
	}
	if cfg.BridgeAddress == (common.Address{}) {
		return nil, fmt.Errorf("%w: bridge address must be non-zero", ErrInvalidPaidMarkerConfig)
	}
	if sender == nil || signer == nil {
		return nil, fmt.Errorf("%w: nil sender/signer", ErrInvalidPaidMarkerConfig)
	}
	return &BasePaidMarker{
		cfg:    cfg,
		sender: sender,
		signer: signer,
	}, nil
}

func (m *BasePaidMarker) MarkPaid(ctx context.Context, ids [][32]byte) error {
	if m == nil || m.sender == nil || m.signer == nil {
		return fmt.Errorf("%w: nil paid marker", ErrInvalidPaidMarkerConfig)
	}
	sortedIDs, err := sortWithdrawalIDs(ids)
	if err != nil {
		return err
	}

	digest, err := checkpoint.MarkWithdrawPaidDigest(sortedIDs, m.cfg.BaseChainID, m.cfg.BridgeAddress)
	if err != nil {
		return err
	}
	sigs, err := m.signer.SignExtendDigest(ctx, digest)
	if err != nil {
		return err
	}

	withdrawalIDs := make([]common.Hash, 0, len(sortedIDs))
	for _, id := range sortedIDs {
		withdrawalIDs = append(withdrawalIDs, common.Hash(id))
	}

	calldata, err := bridgeabi.PackMarkWithdrawPaidBatchCalldata(withdrawalIDs, sigs)
	if err != nil {
		return err
	}

	res, err := m.sender.Send(ctx, httpapi.SendRequest{
		To:       m.cfg.BridgeAddress.Hex(),
		Data:     hexutil.Encode(calldata),
		GasLimit: m.cfg.GasLimit,
	})
	if err != nil {
		return err
	}
	if res.TxHash == "" {
		return fmt.Errorf("withdrawcoordinator: mark paid tx missing hash")
	}
	if res.Receipt == nil {
		return fmt.Errorf("withdrawcoordinator: mark paid tx missing receipt")
	}
	if res.Receipt.Status != 1 {
		return fmt.Errorf("withdrawcoordinator: mark paid tx reverted")
	}
	return nil
}

func sortWithdrawalIDs(ids [][32]byte) ([][32]byte, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: empty ids", ErrInvalidPaidMarkerConfig)
	}
	sorted := make([][32]byte, len(ids))
	copy(sorted, ids)
	slices.SortFunc(sorted, func(a, b [32]byte) int {
		return bytes.Compare(a[:], b[:])
	})
	return sorted, nil
}
