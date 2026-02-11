package withdrawcoordinator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
)

var ErrInvalidExpiryExtenderConfig = errors.New("withdrawcoordinator: invalid expiry extender config")

type ExtendDigestSigner interface {
	SignExtendDigest(ctx context.Context, digest common.Hash) ([][]byte, error)
}

type BaseExpiryExtenderConfig struct {
	BaseChainID   uint64
	BridgeAddress common.Address
	GasLimit      uint64
}

type BaseExpiryExtender struct {
	cfg BaseExpiryExtenderConfig

	sender httpapiSender
	signer ExtendDigestSigner
}

type httpapiSender interface {
	Send(ctx context.Context, req httpapi.SendRequest) (httpapi.SendResponse, error)
}

func NewBaseExpiryExtender(cfg BaseExpiryExtenderConfig, sender httpapiSender, signer ExtendDigestSigner) (*BaseExpiryExtender, error) {
	if cfg.BaseChainID == 0 {
		return nil, fmt.Errorf("%w: base chain id must be non-zero", ErrInvalidExpiryExtenderConfig)
	}
	if cfg.BridgeAddress == (common.Address{}) {
		return nil, fmt.Errorf("%w: bridge address must be non-zero", ErrInvalidExpiryExtenderConfig)
	}
	if sender == nil || signer == nil {
		return nil, fmt.Errorf("%w: nil sender/signer", ErrInvalidExpiryExtenderConfig)
	}
	return &BaseExpiryExtender{
		cfg:    cfg,
		sender: sender,
		signer: signer,
	}, nil
}

func (e *BaseExpiryExtender) Extend(ctx context.Context, ids [][32]byte, newExpiry time.Time) error {
	if e == nil || e.sender == nil || e.signer == nil {
		return fmt.Errorf("%w: nil extender", ErrInvalidExpiryExtenderConfig)
	}
	if len(ids) == 0 {
		return fmt.Errorf("%w: empty ids", ErrInvalidExpiryExtenderConfig)
	}
	newExpiryUnix := uint64(newExpiry.UTC().Unix())
	if newExpiryUnix == 0 {
		return fmt.Errorf("%w: new expiry must be non-zero", ErrInvalidExpiryExtenderConfig)
	}

	digest, err := checkpoint.ExtendWithdrawDigest(ids, newExpiryUnix, e.cfg.BaseChainID, e.cfg.BridgeAddress)
	if err != nil {
		return err
	}
	sigs, err := e.signer.SignExtendDigest(ctx, digest)
	if err != nil {
		return err
	}

	withdrawalIDs := make([]common.Hash, 0, len(ids))
	for _, id := range ids {
		withdrawalIDs = append(withdrawalIDs, common.Hash(id))
	}

	calldata, err := bridgeabi.PackExtendWithdrawExpiryBatchCalldata(withdrawalIDs, newExpiryUnix, sigs)
	if err != nil {
		return err
	}

	res, err := e.sender.Send(ctx, httpapi.SendRequest{
		To:       e.cfg.BridgeAddress.Hex(),
		Data:     hexutil.Encode(calldata),
		GasLimit: e.cfg.GasLimit,
	})
	if err != nil {
		return err
	}
	if res.TxHash == "" {
		return fmt.Errorf("withdrawcoordinator: extend expiry tx missing hash")
	}
	if res.Receipt == nil {
		return fmt.Errorf("withdrawcoordinator: extend expiry tx missing receipt")
	}
	if res.Receipt.Status != 1 {
		return fmt.Errorf("withdrawcoordinator: extend expiry tx reverted")
	}
	return nil
}

type LocalExtendSigner struct {
	keys []*ecdsa.PrivateKey
}

func NewLocalExtendSigner(keys []*ecdsa.PrivateKey) (*LocalExtendSigner, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: empty signing key set", ErrInvalidExpiryExtenderConfig)
	}
	cp := make([]*ecdsa.PrivateKey, 0, len(keys))
	for i, k := range keys {
		if k == nil {
			return nil, fmt.Errorf("%w: nil key at index %d", ErrInvalidExpiryExtenderConfig, i)
		}
		cp = append(cp, k)
	}
	return &LocalExtendSigner{keys: cp}, nil
}

func (s *LocalExtendSigner) SignExtendDigest(_ context.Context, digest common.Hash) ([][]byte, error) {
	if s == nil || len(s.keys) == 0 {
		return nil, fmt.Errorf("%w: nil local extend signer", ErrInvalidExpiryExtenderConfig)
	}

	type pair struct {
		addr common.Address
		sig  []byte
	}
	pairs := make([]pair, 0, len(s.keys))

	for _, k := range s.keys {
		sig, err := checkpoint.SignDigest(k, digest)
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, pair{
			addr: crypto.PubkeyToAddress(k.PublicKey),
			sig:  sig,
		})
	}

	slices.SortFunc(pairs, func(a, b pair) int {
		return bytes.Compare(a.addr[:], b.addr[:])
	})
	for i := 1; i < len(pairs); i++ {
		if pairs[i].addr == pairs[i-1].addr {
			return nil, fmt.Errorf("%w: duplicate signer address %s", ErrInvalidExpiryExtenderConfig, pairs[i].addr.Hex())
		}
	}

	out := make([][]byte, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.sig)
	}
	return out, nil
}
