package withdrawcoordinator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/juno-intents/intents-juno/internal/junorpc"
)

var ErrInvalidJunoRuntimeConfig = errors.New("withdrawcoordinator: invalid juno runtime config")

type JunoRPC interface {
	SendRawTransaction(ctx context.Context, rawTx []byte) (string, error)
	GetRawTransaction(ctx context.Context, txid string) (junorpc.RawTransaction, error)
	GetBlockChainInfo(ctx context.Context) (junorpc.BlockChainInfo, error)
}

type JunoBroadcaster struct {
	rpc JunoRPC
}

func NewJunoBroadcaster(rpc JunoRPC) (*JunoBroadcaster, error) {
	if rpc == nil {
		return nil, fmt.Errorf("%w: nil rpc client", ErrInvalidJunoRuntimeConfig)
	}
	return &JunoBroadcaster{rpc: rpc}, nil
}

func (b *JunoBroadcaster) Broadcast(ctx context.Context, rawTx []byte) (string, error) {
	if b == nil || b.rpc == nil {
		return "", fmt.Errorf("%w: nil broadcaster", ErrInvalidJunoRuntimeConfig)
	}
	txid, err := b.rpc.SendRawTransaction(ctx, rawTx)
	if err != nil {
		return "", err
	}
	if txid == "" {
		return "", fmt.Errorf("withdrawcoordinator: empty txid from junocashd")
	}
	return txid, nil
}

type JunoConfirmer struct {
	rpc              JunoRPC
	minConfirmations int64
	pollInterval     time.Duration
	maxWait          time.Duration
	now              func() time.Time
	runtimeSettings  RuntimeSettingsProvider
}

var (
	ErrConfirmationPending = errors.New("withdrawcoordinator: confirmation pending")
	ErrConfirmationMissing = errors.New("withdrawcoordinator: transaction missing from mempool and chain")
)

func NewJunoConfirmer(rpc JunoRPC, minConfirmations int64, pollInterval time.Duration, maxWait time.Duration) (*JunoConfirmer, error) {
	if rpc == nil {
		return nil, fmt.Errorf("%w: nil rpc client", ErrInvalidJunoRuntimeConfig)
	}
	if minConfirmations <= 0 {
		return nil, fmt.Errorf("%w: min confirmations must be > 0", ErrInvalidJunoRuntimeConfig)
	}
	if pollInterval <= 0 {
		return nil, fmt.Errorf("%w: poll interval must be > 0", ErrInvalidJunoRuntimeConfig)
	}
	if maxWait <= 0 {
		return nil, fmt.Errorf("%w: max wait must be > 0", ErrInvalidJunoRuntimeConfig)
	}
	return &JunoConfirmer{
		rpc:              rpc,
		minConfirmations: minConfirmations,
		pollInterval:     pollInterval,
		maxWait:          maxWait,
		now:              time.Now,
	}, nil
}

// TipHeight returns the current Juno chain tip height.
func (c *JunoConfirmer) TipHeight(ctx context.Context) (uint64, error) {
	if c == nil || c.rpc == nil {
		return 0, fmt.Errorf("%w: nil confirmer", ErrInvalidJunoRuntimeConfig)
	}
	info, err := c.rpc.GetBlockChainInfo(ctx)
	if err != nil {
		return 0, err
	}
	return info.Blocks, nil
}

// TxStatus checks the status of a Juno transaction.
// Returns TxStatusConfirmed, TxStatusMempool, or TxStatusMissing.
func (c *JunoConfirmer) TxStatus(ctx context.Context, txid string) (string, error) {
	if c == nil || c.rpc == nil {
		return "", fmt.Errorf("%w: nil confirmer", ErrInvalidJunoRuntimeConfig)
	}
	tx, err := c.rpc.GetRawTransaction(ctx, txid)
	if err != nil {
		if errors.Is(err, junorpc.ErrTxNotFound) {
			return TxStatusMissing, nil
		}
		return "", err
	}
	if tx.Confirmations > 0 {
		return TxStatusConfirmed, nil
	}
	return TxStatusMempool, nil
}

func (c *JunoConfirmer) WaitConfirmed(ctx context.Context, txid string) error {
	if c == nil || c.rpc == nil {
		return fmt.Errorf("%w: nil confirmer", ErrInvalidJunoRuntimeConfig)
	}
	if c.now == nil {
		c.now = time.Now
	}
	minConfirmations, err := currentWithdrawBatchConfirmations(c.runtimeSettings, c.minConfirmations)
	if err != nil {
		return err
	}

	deadline := c.now().Add(c.maxWait)
	seenTx := false

	for {
		if !c.now().Before(deadline) {
			if seenTx {
				return ErrConfirmationPending
			}
			return ErrConfirmationMissing
		}

		tx, err := c.rpc.GetRawTransaction(ctx, txid)
		if err == nil {
			seenTx = true
			if tx.Confirmations >= minConfirmations {
				return nil
			}
		} else if !errors.Is(err, junorpc.ErrTxNotFound) {
			return err
		}

		wait := c.pollInterval
		if remain := deadline.Sub(c.now()); remain < wait {
			wait = remain
		}
		if wait <= 0 {
			if seenTx {
				return ErrConfirmationPending
			}
			return ErrConfirmationMissing
		}

		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (c *JunoConfirmer) WithRuntimeSettings(provider RuntimeSettingsProvider) *JunoConfirmer {
	if c == nil {
		return nil
	}
	c.runtimeSettings = provider
	return c
}
