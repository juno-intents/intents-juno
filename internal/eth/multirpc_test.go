package eth

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type stubMultiRPCClient struct {
	receipt    *types.Receipt
	receiptErr error

	logs    []types.Log
	logsErr error

	callResult []byte
	callErr    error

	closed bool
}

func (s *stubMultiRPCClient) TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	if s.receiptErr != nil {
		return nil, s.receiptErr
	}
	return s.receipt, nil
}

func (s *stubMultiRPCClient) FilterLogs(context.Context, ethereum.FilterQuery) ([]types.Log, error) {
	if s.logsErr != nil {
		return nil, s.logsErr
	}
	return append([]types.Log(nil), s.logs...), nil
}

func (s *stubMultiRPCClient) CallContract(context.Context, ethereum.CallMsg, *big.Int) ([]byte, error) {
	if s.callErr != nil {
		return nil, s.callErr
	}
	return append([]byte(nil), s.callResult...), nil
}

func (s *stubMultiRPCClient) Close() {
	s.closed = true
}

func TestNewMultiRPCClient_RequiresAtLeastOneClient(t *testing.T) {
	t.Parallel()

	if _, err := NewMultiRPCClient(); err == nil {
		t.Fatalf("expected error")
	}
}

func TestMultiRPCClient_TransactionReceiptFallsBackToLaterClient(t *testing.T) {
	t.Parallel()

	want := &types.Receipt{Status: types.ReceiptStatusSuccessful}
	client, err := NewMultiRPCClient(
		&stubMultiRPCClient{receiptErr: errors.New("primary down")},
		&stubMultiRPCClient{receipt: want},
	)
	if err != nil {
		t.Fatalf("NewMultiRPCClient: %v", err)
	}

	got, err := client.TransactionReceipt(context.Background(), common.HexToHash("0x01"))
	if err != nil {
		t.Fatalf("TransactionReceipt: %v", err)
	}
	if got != want {
		t.Fatalf("receipt mismatch")
	}
}

func TestMultiRPCClient_CallContractFallsBackToLaterClient(t *testing.T) {
	t.Parallel()

	want := []byte{0xaa, 0xbb}
	client, err := NewMultiRPCClient(
		&stubMultiRPCClient{callErr: errors.New("primary down")},
		&stubMultiRPCClient{callResult: want},
	)
	if err != nil {
		t.Fatalf("NewMultiRPCClient: %v", err)
	}

	got, err := client.CallContract(context.Background(), ethereum.CallMsg{}, nil)
	if err != nil {
		t.Fatalf("CallContract: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("call result mismatch: got %x want %x", got, want)
	}
}

func TestMultiRPCClient_FilterLogsUnionsAndDeduplicatesAcrossClients(t *testing.T) {
	t.Parallel()

	logA := types.Log{
		Address:     common.HexToAddress("0x00000000000000000000000000000000000000aa"),
		BlockNumber: 10,
		TxHash:      common.HexToHash("0x100"),
		TxIndex:     1,
		Index:       2,
	}
	logB := types.Log{
		Address:     common.HexToAddress("0x00000000000000000000000000000000000000bb"),
		BlockNumber: 12,
		TxHash:      common.HexToHash("0x200"),
		TxIndex:     0,
		Index:       1,
	}

	client, err := NewMultiRPCClient(
		&stubMultiRPCClient{logs: []types.Log{logA}},
		&stubMultiRPCClient{logs: []types.Log{logA, logB}},
		&stubMultiRPCClient{logsErr: errors.New("temporary 503")},
	)
	if err != nil {
		t.Fatalf("NewMultiRPCClient: %v", err)
	}

	got, err := client.FilterLogs(context.Background(), ethereum.FilterQuery{})
	if err != nil {
		t.Fatalf("FilterLogs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("log count = %d, want 2", len(got))
	}
	if got[0].TxHash != logA.TxHash || got[1].TxHash != logB.TxHash {
		t.Fatalf("unexpected log order: got %x then %x", got[0].TxHash, got[1].TxHash)
	}
}

func TestMultiRPCClient_CloseClosesAllClients(t *testing.T) {
	t.Parallel()

	first := &stubMultiRPCClient{}
	second := &stubMultiRPCClient{}
	client, err := NewMultiRPCClient(first, second)
	if err != nil {
		t.Fatalf("NewMultiRPCClient: %v", err)
	}

	client.Close()
	if !first.closed || !second.closed {
		t.Fatalf("expected both clients to be closed")
	}
}
