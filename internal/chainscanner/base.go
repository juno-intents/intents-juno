package chainscanner

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// WithdrawRequestedEvent represents a parsed Bridge.WithdrawRequested log.
type WithdrawRequestedEvent struct {
	WithdrawalID [32]byte
	Requester    common.Address
	Amount       *big.Int
	RecipientUA  []byte
	Expiry       uint64
	FeeBps       uint64
	BlockNumber  uint64
	TxHash       common.Hash
	LogIndex     uint
}

// withdrawRequestedTopic0 is keccak256("WithdrawRequested(bytes32,address,uint256,bytes,uint64,uint96)").
var withdrawRequestedTopic0 = crypto.Keccak256Hash([]byte("WithdrawRequested(bytes32,address,uint256,bytes,uint64,uint96)"))

// BaseScannerConfig configures the BaseScanner.
type BaseScannerConfig struct {
	Client           EthClient
	BridgeAddr       common.Address
	StateStore       StateStore
	ServiceName      string
	MaxBlocksPerPoll int64
	PollInterval     time.Duration
}

// EthClient is the subset of ethclient.Client used by the scanner.
type EthClient interface {
	BlockNumber(ctx context.Context) (uint64, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
}

// Verify ethclient.Client implements EthClient at compile time.
var _ EthClient = (*ethclient.Client)(nil)

// BaseScanner polls Base chain for WithdrawRequested events.
type BaseScanner struct {
	client           EthClient
	bridgeAddr       common.Address
	stateStore       StateStore
	serviceName      string
	maxBlocksPerPoll int64
	pollInterval     time.Duration
}

// NewBaseScanner creates a new BaseScanner from the provided config.
func NewBaseScanner(cfg BaseScannerConfig) (*BaseScanner, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidConfig)
	}
	if cfg.BridgeAddr == (common.Address{}) {
		return nil, fmt.Errorf("%w: empty bridge address", ErrInvalidConfig)
	}
	if cfg.StateStore == nil {
		return nil, fmt.Errorf("%w: nil state store", ErrInvalidConfig)
	}
	svc := strings.TrimSpace(cfg.ServiceName)
	if svc == "" {
		svc = "base-event-scanner"
	}
	maxBlocks := cfg.MaxBlocksPerPoll
	if maxBlocks <= 0 {
		maxBlocks = 1000
	}
	pollInterval := cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}

	return &BaseScanner{
		client:           cfg.Client,
		bridgeAddr:       cfg.BridgeAddr,
		stateStore:       cfg.StateStore,
		serviceName:      svc,
		maxBlocksPerPoll: maxBlocks,
		pollInterval:     pollInterval,
	}, nil
}

// Run starts the scanner loop. It fetches logs from the chain and calls publish for
// each parsed WithdrawRequested event. Run blocks until ctx is cancelled. If startBlock
// is > 0 and no state exists in the store, scanning begins from startBlock.
func (s *BaseScanner) Run(ctx context.Context, startBlock int64, publish func(ctx context.Context, event WithdrawRequestedEvent) error) error {
	if publish == nil {
		return fmt.Errorf("%w: nil publish function", ErrInvalidConfig)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := s.poll(ctx, startBlock, publish); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// Non-fatal error: wait and retry.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(s.pollInterval):
			}
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.pollInterval):
		}
	}
}

func (s *BaseScanner) poll(ctx context.Context, startBlock int64, publish func(ctx context.Context, event WithdrawRequestedEvent) error) error {
	currentBlock, err := s.client.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("get block number: %w", err)
	}

	lastHeight, err := s.rewindToCanonicalHeight(ctx, int64(currentBlock))
	if err != nil {
		return err
	}

	fromBlock := lastHeight + 1
	if lastHeight == 0 && startBlock > 0 {
		fromBlock = startBlock
	}

	if fromBlock > int64(currentBlock) {
		return nil // nothing to scan
	}

	toBlock := fromBlock + s.maxBlocksPerPoll - 1
	if toBlock > int64(currentBlock) {
		toBlock = int64(currentBlock)
	}

	headers, err := s.loadHeaders(ctx, lastHeight, fromBlock, toBlock)
	if err != nil {
		return err
	}

	events, err := s.fetchAndParse(ctx, fromBlock, toBlock)
	if err != nil {
		return err
	}

	for _, event := range events {
		if err := publish(ctx, event); err != nil {
			return fmt.Errorf("publish event: %w", err)
		}
	}

	for _, hdr := range headers {
		if err := s.stateStore.StoreBlockRef(ctx, s.serviceName, BlockRef{
			Height:     hdr.Number.Int64(),
			Hash:       hdr.Hash(),
			ParentHash: hdr.ParentHash,
		}); err != nil {
			return fmt.Errorf("store block ref: %w", err)
		}
	}

	if err := s.stateStore.SetLastHeight(ctx, s.serviceName, toBlock); err != nil {
		return fmt.Errorf("set last height: %w", err)
	}

	return nil
}

func (s *BaseScanner) rewindToCanonicalHeight(ctx context.Context, currentBlock int64) (int64, error) {
	lastHeight, err := s.stateStore.GetLastHeight(ctx, s.serviceName)
	if err != nil {
		return 0, fmt.Errorf("get last height: %w", err)
	}
	if lastHeight <= 0 {
		return 0, nil
	}
	if _, ok, err := s.stateStore.GetBlockRef(ctx, s.serviceName, lastHeight); err != nil {
		return 0, fmt.Errorf("get latest block ref: %w", err)
	} else if !ok {
		return lastHeight, nil
	}

	probeHeight := lastHeight
	if probeHeight > currentBlock {
		probeHeight = currentBlock
	}

	for probeHeight > 0 {
		ref, ok, err := s.stateStore.GetBlockRef(ctx, s.serviceName, probeHeight)
		if err != nil {
			return 0, fmt.Errorf("get stored block ref: %w", err)
		}
		if !ok {
			probeHeight--
			continue
		}

		header, err := s.client.HeaderByNumber(ctx, big.NewInt(probeHeight))
		if err != nil {
			return 0, fmt.Errorf("get header %d: %w", probeHeight, err)
		}
		if header.Hash() == ref.Hash {
			if probeHeight != lastHeight {
				if err := s.stateStore.DeleteBlockRefsFromHeight(ctx, s.serviceName, probeHeight+1); err != nil {
					return 0, fmt.Errorf("delete rewound block refs: %w", err)
				}
				if err := s.stateStore.SetLastHeight(ctx, s.serviceName, probeHeight); err != nil {
					return 0, fmt.Errorf("rewind last height: %w", err)
				}
			}
			return probeHeight, nil
		}

		probeHeight--
	}

	if err := s.stateStore.DeleteBlockRefsFromHeight(ctx, s.serviceName, 1); err != nil {
		return 0, fmt.Errorf("clear block refs after reorg: %w", err)
	}
	if err := s.stateStore.SetLastHeight(ctx, s.serviceName, 0); err != nil {
		return 0, fmt.Errorf("reset last height after reorg: %w", err)
	}
	return 0, nil
}

func (s *BaseScanner) loadHeaders(ctx context.Context, lastHeight, fromBlock, toBlock int64) ([]*types.Header, error) {
	headers := make([]*types.Header, 0, toBlock-fromBlock+1)

	var lastHash common.Hash
	hasLastHash := false
	if lastHeight > 0 {
		ref, ok, err := s.stateStore.GetBlockRef(ctx, s.serviceName, lastHeight)
		if err != nil {
			return nil, fmt.Errorf("get prior block ref: %w", err)
		}
		if ok {
			lastHash = ref.Hash
			hasLastHash = true
		}
	}

	for height := fromBlock; height <= toBlock; height++ {
		header, err := s.client.HeaderByNumber(ctx, big.NewInt(height))
		if err != nil {
			return nil, fmt.Errorf("get header %d: %w", height, err)
		}
		if height == fromBlock && hasLastHash && header.ParentHash != lastHash {
			return nil, fmt.Errorf("header continuity mismatch at height %d", height)
		}
		if len(headers) > 0 {
			prev := headers[len(headers)-1]
			if header.ParentHash != prev.Hash() {
				return nil, fmt.Errorf("header continuity mismatch at height %d", height)
			}
		}
		headers = append(headers, header)
	}

	return headers, nil
}

func (s *BaseScanner) fetchAndParse(ctx context.Context, fromBlock, toBlock int64) ([]WithdrawRequestedEvent, error) {
	query := ethereum.FilterQuery{
		FromBlock: big.NewInt(fromBlock),
		ToBlock:   big.NewInt(toBlock),
		Addresses: []common.Address{s.bridgeAddr},
		Topics:    [][]common.Hash{{withdrawRequestedTopic0}},
	}

	logs, err := s.client.FilterLogs(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("filter logs [%d, %d]: %w", fromBlock, toBlock, err)
	}

	events := make([]WithdrawRequestedEvent, 0, len(logs))
	for _, lg := range logs {
		event, err := parseWithdrawRequestedLog(lg)
		if err != nil {
			return nil, fmt.Errorf("parse log at block %d tx %s index %d: %w", lg.BlockNumber, lg.TxHash.Hex(), lg.Index, err)
		}
		events = append(events, event)
	}
	return events, nil
}

// parseWithdrawRequestedLog decodes a single raw log into a WithdrawRequestedEvent.
//
// Event signature:
//
//	WithdrawRequested(bytes32 indexed withdrawalId, address indexed requester, uint256 amount, bytes recipientUA, uint64 expiry, uint96 feeBps)
//
// Topics: [topic0, withdrawalId, requester]
// Data: abi.encode(amount, recipientUA, expiry, feeBps) — note: recipientUA is dynamic.
func parseWithdrawRequestedLog(lg types.Log) (WithdrawRequestedEvent, error) {
	if len(lg.Topics) < 3 {
		return WithdrawRequestedEvent{}, fmt.Errorf("expected >= 3 topics, got %d", len(lg.Topics))
	}
	if lg.Topics[0] != withdrawRequestedTopic0 {
		return WithdrawRequestedEvent{}, fmt.Errorf("unexpected topic0: %s", lg.Topics[0].Hex())
	}

	// Data layout (ABI-encoded with dynamic bytes):
	// offset 0:   amount (uint256) — 32 bytes
	// offset 32:  recipientUA offset (uint256) — 32 bytes (points to dynamic data)
	// offset 64:  expiry (uint64 padded to uint256) — 32 bytes
	// offset 96:  feeBps (uint96 padded to uint256) — 32 bytes
	// offset 128: recipientUA length (uint256) — 32 bytes
	// offset 160: recipientUA data — ceil(len/32)*32 bytes
	if len(lg.Data) < 160 {
		return WithdrawRequestedEvent{}, fmt.Errorf("data too short: %d bytes", len(lg.Data))
	}

	amount := new(big.Int).SetBytes(lg.Data[0:32])

	// recipientUA offset — should be 128 (4 * 32)
	recipientUAOffset := new(big.Int).SetBytes(lg.Data[32:64])
	if !recipientUAOffset.IsUint64() {
		return WithdrawRequestedEvent{}, fmt.Errorf("recipientUA offset too large")
	}
	off := recipientUAOffset.Uint64()
	if off+32 > uint64(len(lg.Data)) {
		return WithdrawRequestedEvent{}, fmt.Errorf("recipientUA offset out of bounds")
	}
	recipientUALen := new(big.Int).SetBytes(lg.Data[off : off+32])
	if !recipientUALen.IsUint64() {
		return WithdrawRequestedEvent{}, fmt.Errorf("recipientUA length too large")
	}
	uaLen := recipientUALen.Uint64()
	if off+32+uaLen > uint64(len(lg.Data)) {
		return WithdrawRequestedEvent{}, fmt.Errorf("recipientUA data out of bounds")
	}
	recipientUA := make([]byte, uaLen)
	copy(recipientUA, lg.Data[off+32:off+32+uaLen])

	expiry := new(big.Int).SetBytes(lg.Data[64:96])
	if !expiry.IsUint64() {
		return WithdrawRequestedEvent{}, fmt.Errorf("expiry out of range")
	}

	feeBps := new(big.Int).SetBytes(lg.Data[96:128])
	if !feeBps.IsUint64() {
		return WithdrawRequestedEvent{}, fmt.Errorf("feeBps out of range")
	}

	var withdrawalID [32]byte
	copy(withdrawalID[:], lg.Topics[1][:])

	return WithdrawRequestedEvent{
		WithdrawalID: withdrawalID,
		Requester:    common.BytesToAddress(lg.Topics[2].Bytes()),
		Amount:       amount,
		RecipientUA:  recipientUA,
		Expiry:       expiry.Uint64(),
		FeeBps:       feeBps.Uint64(),
		BlockNumber:  lg.BlockNumber,
		TxHash:       lg.TxHash,
		LogIndex:     lg.Index,
	}, nil
}
