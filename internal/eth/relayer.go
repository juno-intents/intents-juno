package eth

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

var ErrInvalidRelayerConfig = errors.New("eth: invalid relayer config")

type Backend interface {
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error)
	SendTransaction(ctx context.Context, tx *types.Transaction) error
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
}

type RelayerConfig struct {
	ChainID            *big.Int
	GasLimitMultiplier float64
	MinTipCap          *big.Int

	ReceiptPollInterval time.Duration

	ReplaceAfter           time.Duration
	MaxReplacements        int
	ReplacementBumpPercent int
	MinReplacementTipBump  *big.Int
	MinReplacementFeeBump  *big.Int

	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

type Relayer struct {
	backend Backend
	cfg     RelayerConfig

	signers []Signer
	nonces  map[common.Address]*NonceManager
	rr      uint32
}

type TxRequest struct {
	To       common.Address
	Data     []byte
	Value    *big.Int
	GasLimit uint64 // optional; 0 => estimate
}

type SendResult struct {
	From         common.Address
	Nonce        uint64
	TxHash       common.Hash
	Receipt      *types.Receipt
	Replacements int
}

func NewRelayer(backend Backend, signers []Signer, cfg RelayerConfig) (*Relayer, error) {
	if backend == nil || len(signers) == 0 {
		return nil, ErrInvalidRelayerConfig
	}
	if cfg.ChainID == nil || cfg.ChainID.Sign() <= 0 {
		return nil, ErrInvalidRelayerConfig
	}
	if cfg.GasLimitMultiplier <= 0 {
		return nil, ErrInvalidRelayerConfig
	}
	if cfg.MinTipCap == nil || cfg.MinTipCap.Sign() < 0 {
		return nil, ErrInvalidRelayerConfig
	}
	if cfg.ReceiptPollInterval <= 0 {
		return nil, ErrInvalidRelayerConfig
	}
	if cfg.MaxReplacements < 0 {
		return nil, ErrInvalidRelayerConfig
	}
	if cfg.MaxReplacements > 0 {
		if cfg.ReplaceAfter <= 0 {
			return nil, ErrInvalidRelayerConfig
		}
		if cfg.ReplacementBumpPercent <= 0 {
			return nil, ErrInvalidRelayerConfig
		}
		if cfg.MinReplacementTipBump == nil || cfg.MinReplacementFeeBump == nil {
			return nil, ErrInvalidRelayerConfig
		}
		if cfg.MinReplacementTipBump.Sign() < 0 || cfg.MinReplacementFeeBump.Sign() < 0 {
			return nil, ErrInvalidRelayerConfig
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleepCtx
	}

	nonces := make(map[common.Address]*NonceManager, len(signers))
	for _, s := range signers {
		if s == nil {
			return nil, ErrInvalidRelayerConfig
		}
		addr := s.Address()
		if (addr == common.Address{}) {
			return nil, ErrInvalidRelayerConfig
		}
		if _, ok := nonces[addr]; ok {
			return nil, fmt.Errorf("%w: duplicate signer address %s", ErrInvalidRelayerConfig, addr)
		}
		nonces[addr] = NewNonceManager(backend, addr)
	}

	return &Relayer{
		backend: backend,
		cfg:     cfg,
		signers: signers,
		nonces:  nonces,
		rr:      0,
	}, nil
}

func (r *Relayer) pickSigner() (Signer, *NonceManager) {
	i := atomic.AddUint32(&r.rr, 1)
	s := r.signers[int(i)%len(r.signers)]
	return s, r.nonces[s.Address()]
}

func (r *Relayer) SendAndWaitMined(ctx context.Context, req TxRequest) (SendResult, error) {
	s, nm := r.pickSigner()
	from := s.Address()

	value := req.Value
	if value == nil {
		value = big.NewInt(0)
	}

	gasLimit := req.GasLimit
	if gasLimit == 0 {
		est, err := r.backend.EstimateGas(ctx, ethereum.CallMsg{
			From:  from,
			To:    &req.To,
			Value: value,
			Data:  req.Data,
		})
		if err != nil {
			return SendResult{}, err
		}
		gasLimit = applyGasMultiplier(est, r.cfg.GasLimitMultiplier)
	}

	suggestedTip, err := r.backend.SuggestGasTipCap(ctx)
	if err != nil {
		return SendResult{}, err
	}
	header, err := r.backend.HeaderByNumber(ctx, nil)
	if err != nil {
		return SendResult{}, err
	}
	if header.BaseFee == nil || header.BaseFee.Sign() < 0 {
		return SendResult{}, fmt.Errorf("eth: missing baseFee in latest header")
	}

	tipCap, feeCap, err := Calc1559Fees(header.BaseFee, suggestedTip, r.cfg.MinTipCap)
	if err != nil {
		return SendResult{}, err
	}

	nonce, err := nm.Next(ctx)
	if err != nil {
		return SendResult{}, err
	}

	gas := gasLimit
	to := req.To
	data := req.Data

	makeSigned := func(tip, fee *big.Int) (*types.Transaction, common.Hash, error) {
		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   r.cfg.ChainID,
			Nonce:     nonce,
			GasTipCap: tip,
			GasFeeCap: fee,
			Gas:       gas,
			To:        &to,
			Value:     value,
			Data:      data,
		})
		signed, err := s.SignTx(tx, r.cfg.ChainID)
		if err != nil {
			return nil, common.Hash{}, err
		}
		return signed, signed.Hash(), nil
	}

	signed, h, err := makeSigned(tipCap, feeCap)
	if err != nil {
		return SendResult{}, err
	}
	if err := r.backend.SendTransaction(ctx, signed); err != nil {
		return SendResult{}, err
	}

	sent := []common.Hash{h}
	lastSentAt := r.cfg.Now()
	replacements := 0

	for {
		for _, txh := range sent {
			receipt, err := r.backend.TransactionReceipt(ctx, txh)
			if err == nil {
				return SendResult{
					From:         from,
					Nonce:        nonce,
					TxHash:       txh,
					Receipt:      receipt,
					Replacements: replacements,
				}, nil
			}
			if !errors.Is(err, ethereum.NotFound) {
				return SendResult{}, err
			}
		}

		if r.cfg.MaxReplacements > 0 && replacements < r.cfg.MaxReplacements && r.cfg.Now().Sub(lastSentAt) >= r.cfg.ReplaceAfter {
			var err error
			tipCap, feeCap, err = Bump1559Fees(tipCap, feeCap, r.cfg.ReplacementBumpPercent, r.cfg.MinReplacementTipBump, r.cfg.MinReplacementFeeBump)
			if err != nil {
				return SendResult{}, err
			}

			signed, h, err := makeSigned(tipCap, feeCap)
			if err != nil {
				return SendResult{}, err
			}
			if err := r.backend.SendTransaction(ctx, signed); err != nil {
				return SendResult{}, err
			}
			sent = append(sent, h)
			lastSentAt = r.cfg.Now()
			replacements++
			continue
		}

		if err := r.cfg.Sleep(ctx, r.cfg.ReceiptPollInterval); err != nil {
			return SendResult{}, err
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func applyGasMultiplier(est uint64, mult float64) uint64 {
	if mult <= 1 {
		return est
	}
	out := uint64(math.Ceil(float64(est) * mult))
	if out < est {
		// overflow or float error; fall back to the estimate.
		return est
	}
	return out
}
