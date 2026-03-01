package e2eorch

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// WithdrawalOnChainView mirrors the return values of Bridge.getWithdrawal(bytes32).
type WithdrawalOnChainView struct {
	Requester   common.Address
	Amount      *big.Int
	Expiry      uint64
	FeeBps      uint64 // uint96 on-chain, fits in uint64
	Finalized   bool
	Refunded    bool
	RecipientUA []byte
}

// Minimal ABI fragments used for read-only calls.
var (
	erc20ABI  abi.ABI
	bridgeReadABI abi.ABI
)

func init() {
	var err error

	erc20ABI, err = abi.JSON(strings.NewReader(erc20BalanceOfABIJSON))
	if err != nil {
		panic(fmt.Sprintf("e2eorch: parse ERC20 ABI: %v", err))
	}

	bridgeReadABI, err = abi.JSON(strings.NewReader(bridgeReadABIJSON))
	if err != nil {
		panic(fmt.Sprintf("e2eorch: parse Bridge read ABI: %v", err))
	}
}

// ReadWJunoBalance calls ERC20.balanceOf(account) on the wJUNO contract.
func ReadWJunoBalance(ctx context.Context, client *ethclient.Client, wjunoAddr, account common.Address) (*big.Int, error) {
	data, err := erc20ABI.Pack("balanceOf", account)
	if err != nil {
		return nil, fmt.Errorf("pack balanceOf: %w", err)
	}

	result, err := client.CallContract(ctx, ethereum.CallMsg{
		To:   &wjunoAddr,
		Data: data,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("call balanceOf on %s: %w", wjunoAddr.Hex(), err)
	}

	vals, err := erc20ABI.Unpack("balanceOf", result)
	if err != nil {
		return nil, fmt.Errorf("unpack balanceOf: %w", err)
	}
	if len(vals) != 1 {
		return nil, fmt.Errorf("balanceOf: expected 1 return value, got %d", len(vals))
	}
	bal, ok := vals[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("balanceOf: unexpected type %T", vals[0])
	}
	return bal, nil
}

// ReadDepositUsed calls Bridge.depositUsed(bytes32) and returns true if the
// deposit has already been minted.
func ReadDepositUsed(ctx context.Context, client *ethclient.Client, bridgeAddr common.Address, depositID [32]byte) (bool, error) {
	data, err := bridgeReadABI.Pack("depositUsed", depositID)
	if err != nil {
		return false, fmt.Errorf("pack depositUsed: %w", err)
	}

	result, err := client.CallContract(ctx, ethereum.CallMsg{
		To:   &bridgeAddr,
		Data: data,
	}, nil)
	if err != nil {
		return false, fmt.Errorf("call depositUsed: %w", err)
	}

	vals, err := bridgeReadABI.Unpack("depositUsed", result)
	if err != nil {
		return false, fmt.Errorf("unpack depositUsed: %w", err)
	}
	if len(vals) != 1 {
		return false, fmt.Errorf("depositUsed: expected 1 return value, got %d", len(vals))
	}
	used, ok := vals[0].(bool)
	if !ok {
		return false, fmt.Errorf("depositUsed: unexpected type %T", vals[0])
	}
	return used, nil
}

// ReadWithdrawalView calls Bridge.getWithdrawal(bytes32) and returns the
// full on-chain withdrawal record.
func ReadWithdrawalView(ctx context.Context, client *ethclient.Client, bridgeAddr common.Address, withdrawalID [32]byte) (*WithdrawalOnChainView, error) {
	data, err := bridgeReadABI.Pack("getWithdrawal", withdrawalID)
	if err != nil {
		return nil, fmt.Errorf("pack getWithdrawal: %w", err)
	}

	result, err := client.CallContract(ctx, ethereum.CallMsg{
		To:   &bridgeAddr,
		Data: data,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("call getWithdrawal: %w", err)
	}

	vals, err := bridgeReadABI.Unpack("getWithdrawal", result)
	if err != nil {
		return nil, fmt.Errorf("unpack getWithdrawal: %w", err)
	}
	// getWithdrawal returns 7 values:
	//   address requester, uint256 amount, uint64 expiry, uint96 feeBpsAtRequest,
	//   bool finalized, bool refunded, bytes recipientUA
	if len(vals) != 7 {
		return nil, fmt.Errorf("getWithdrawal: expected 7 return values, got %d", len(vals))
	}

	requester, ok := vals[0].(common.Address)
	if !ok {
		return nil, fmt.Errorf("getWithdrawal: requester type %T", vals[0])
	}
	amount, ok := vals[1].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("getWithdrawal: amount type %T", vals[1])
	}
	expiry, ok := vals[2].(uint64)
	if !ok {
		return nil, fmt.Errorf("getWithdrawal: expiry type %T", vals[2])
	}
	feeBpsRaw, ok := vals[3].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("getWithdrawal: feeBps type %T", vals[3])
	}
	finalized, ok := vals[4].(bool)
	if !ok {
		return nil, fmt.Errorf("getWithdrawal: finalized type %T", vals[4])
	}
	refunded, ok := vals[5].(bool)
	if !ok {
		return nil, fmt.Errorf("getWithdrawal: refunded type %T", vals[5])
	}
	recipientUA, ok := vals[6].([]byte)
	if !ok {
		return nil, fmt.Errorf("getWithdrawal: recipientUA type %T", vals[6])
	}

	return &WithdrawalOnChainView{
		Requester:   requester,
		Amount:      amount,
		Expiry:      expiry,
		FeeBps:      feeBpsRaw.Uint64(),
		Finalized:   finalized,
		Refunded:    refunded,
		RecipientUA: recipientUA,
	}, nil
}

const erc20BalanceOfABIJSON = `[
  {
    "inputs": [{"internalType":"address","name":"account","type":"address"}],
    "name": "balanceOf",
    "outputs": [{"internalType":"uint256","name":"","type":"uint256"}],
    "stateMutability": "view",
    "type": "function"
  }
]`

const bridgeReadABIJSON = `[
  {
    "inputs": [{"internalType":"bytes32","name":"","type":"bytes32"}],
    "name": "depositUsed",
    "outputs": [{"internalType":"bool","name":"","type":"bool"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType":"bytes32","name":"withdrawalId","type":"bytes32"}],
    "name": "getWithdrawal",
    "outputs": [
      {"internalType":"address","name":"requester","type":"address"},
      {"internalType":"uint256","name":"amount","type":"uint256"},
      {"internalType":"uint64","name":"expiry","type":"uint64"},
      {"internalType":"uint96","name":"feeBpsAtRequest","type":"uint96"},
      {"internalType":"bool","name":"finalized","type":"bool"},
      {"internalType":"bool","name":"refunded","type":"bool"},
      {"internalType":"bytes","name":"recipientUA","type":"bytes"}
    ],
    "stateMutability": "view",
    "type": "function"
  }
]`
