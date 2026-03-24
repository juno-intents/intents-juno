package eth

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

type RPCClient interface {
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
	BlockNumber(ctx context.Context) (uint64, error)
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
	Close()
}

type MultiRPCClient struct {
	clients []RPCClient
}

func NewMultiRPCClient(clients ...RPCClient) (*MultiRPCClient, error) {
	filtered := make([]RPCClient, 0, len(clients))
	for _, client := range clients {
		if client == nil {
			continue
		}
		filtered = append(filtered, client)
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("eth: multi rpc client requires at least one backend")
	}
	return &MultiRPCClient{clients: filtered}, nil
}

func DialMultiRPCClient(ctx context.Context, rawURLs string) (*MultiRPCClient, error) {
	urls := splitRPCURLs(rawURLs)
	if len(urls) == 0 {
		return nil, fmt.Errorf("eth: missing rpc url")
	}

	clients := make([]RPCClient, 0, len(urls))
	for _, rawURL := range urls {
		client, err := ethclient.DialContext(ctx, rawURL)
		if err != nil {
			for _, opened := range clients {
				opened.Close()
			}
			return nil, fmt.Errorf("eth: dial %s: %w", rawURL, err)
		}
		clients = append(clients, client)
	}
	return NewMultiRPCClient(clients...)
}

func (c *MultiRPCClient) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	var errs []error
	for _, client := range c.clients {
		receipt, err := client.TransactionReceipt(ctx, txHash)
		if err == nil {
			return receipt, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (c *MultiRPCClient) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	combined := make([]types.Log, 0)
	seen := make(map[string]struct{})
	var (
		errs    []error
		success bool
	)

	for _, client := range c.clients {
		logs, err := filterLogsWithHeadClamp(ctx, client, q)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		success = true
		for _, lg := range logs {
			key := multiRPCLogKey(lg)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			combined = append(combined, lg)
		}
	}
	if !success {
		return nil, errors.Join(errs...)
	}

	sort.Slice(combined, func(i, j int) bool {
		if combined[i].BlockNumber != combined[j].BlockNumber {
			return combined[i].BlockNumber < combined[j].BlockNumber
		}
		if combined[i].TxIndex != combined[j].TxIndex {
			return combined[i].TxIndex < combined[j].TxIndex
		}
		if combined[i].Index != combined[j].Index {
			return combined[i].Index < combined[j].Index
		}
		return combined[i].TxHash.Hex() < combined[j].TxHash.Hex()
	})
	return combined, nil
}

func (c *MultiRPCClient) BlockNumber(ctx context.Context) (uint64, error) {
	var errs []error
	for _, client := range c.clients {
		head, err := client.BlockNumber(ctx)
		if err == nil {
			return head, nil
		}
		errs = append(errs, err)
	}
	return 0, errors.Join(errs...)
}

func filterLogsWithHeadClamp(ctx context.Context, client RPCClient, q ethereum.FilterQuery) ([]types.Log, error) {
	logs, err := client.FilterLogs(ctx, q)
	if err == nil || q.ToBlock == nil || !isFilterLogsRangeBeyondHeadError(err) {
		return logs, err
	}

	head, headErr := client.BlockNumber(ctx)
	if headErr != nil {
		return nil, errors.Join(err, fmt.Errorf("eth: fetch backend head for log query: %w", headErr))
	}

	clampedQuery, ok := clampFilterQueryToHead(q, head)
	if !ok {
		return nil, err
	}
	return client.FilterLogs(ctx, clampedQuery)
}

func clampFilterQueryToHead(q ethereum.FilterQuery, head uint64) (ethereum.FilterQuery, bool) {
	if q.ToBlock == nil {
		return q, true
	}

	clamped := q
	clampedHead := new(big.Int).SetUint64(head)
	if q.FromBlock != nil && q.FromBlock.Cmp(clampedHead) > 0 {
		return ethereum.FilterQuery{}, false
	}
	clamped.ToBlock = clampedHead
	return clamped, true
}

func isFilterLogsRangeBeyondHeadError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "block range extends beyond current head block")
}

func (c *MultiRPCClient) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	var errs []error
	for _, client := range c.clients {
		result, err := client.CallContract(ctx, msg, blockNumber)
		if err == nil {
			return result, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (c *MultiRPCClient) Close() {
	for _, client := range c.clients {
		client.Close()
	}
}

func splitRPCURLs(raw string) []string {
	parts := strings.Split(raw, ",")
	urls := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		urls = append(urls, part)
	}
	return urls
}

func multiRPCLogKey(lg types.Log) string {
	return fmt.Sprintf("%s|%s|%d|%s", lg.Address.Hex(), lg.TxHash.Hex(), lg.Index, lg.BlockHash.Hex())
}
