package backoffice

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Minimal ABI call helpers for on-chain reads. We avoid abigen and instead
// encode call data directly using Solidity selector + ABI packing.

// erc20TotalSupply calls totalSupply() on an ERC-20 contract, returning the raw uint256.
func erc20TotalSupply(ctx context.Context, client *ethclient.Client, token common.Address) (*big.Int, error) {
	// selector: keccak256("totalSupply()") = 0x18160ddd
	data := common.Hex2Bytes("18160ddd")
	return callUint256(ctx, client, token, data)
}

// erc20BalanceOf calls balanceOf(address) on an ERC-20 contract.
func erc20BalanceOf(ctx context.Context, client *ethclient.Client, token common.Address, account common.Address) (*big.Int, error) {
	// selector: keccak256("balanceOf(address)") = 0x70a08231
	data := make([]byte, 4+32)
	copy(data[0:4], common.Hex2Bytes("70a08231"))
	copy(data[4+12:], account.Bytes()) // left-pad address to 32 bytes
	return callUint256(ctx, client, token, data)
}

// registryIsOperator calls OperatorRegistry.isOperator(address) → bool.
func registryIsOperator(ctx context.Context, client *ethclient.Client, registry common.Address, operator common.Address) (bool, error) {
	// selector: keccak256("isOperator(address)") = 0x6d70f7ae
	data := make([]byte, 4+32)
	copy(data[0:4], common.Hex2Bytes("6d70f7ae"))
	copy(data[4+12:], operator.Bytes())
	v, err := callUint256(ctx, client, registry, data)
	if err != nil {
		return false, err
	}
	return v.Sign() != 0, nil
}

// registryGetOperator calls OperatorRegistry.getOperator(address) → (feeRecipient, weight, active).
func registryGetOperator(ctx context.Context, client *ethclient.Client, registry common.Address, operator common.Address) (feeRecipient common.Address, weight *big.Int, active bool, err error) {
	// selector: keccak256("getOperator(address)") = 0x5865c60c
	data := make([]byte, 4+32)
	copy(data[0:4], common.Hex2Bytes("5865c60c"))
	copy(data[4+12:], operator.Bytes())

	out, callErr := callRaw(ctx, client, registry, data)
	if callErr != nil {
		return common.Address{}, nil, false, callErr
	}
	// ABI decode: (address, uint96, bool) packed as 3 words of 32 bytes each
	if len(out) < 96 {
		return common.Address{}, nil, false, fmt.Errorf("getOperator: response too short (%d bytes)", len(out))
	}
	feeRecipient = common.BytesToAddress(out[0:32])
	weight = new(big.Int).SetBytes(out[32:64])
	active = new(big.Int).SetBytes(out[64:96]).Sign() != 0
	return feeRecipient, weight, active, nil
}

// feeDistributorPendingReward calls FeeDistributor.pendingReward(address) → uint256.
func feeDistributorPendingReward(ctx context.Context, client *ethclient.Client, feeDistAddr common.Address, operator common.Address) (*big.Int, error) {
	// selector: keccak256("pendingReward(address)") = 0xf40f0f52
	data := make([]byte, 4+32)
	copy(data[0:4], common.Hex2Bytes("f40f0f52"))
	copy(data[4+12:], operator.Bytes())
	return callUint256(ctx, client, feeDistAddr, data)
}

// feeDistributorAccFeePerWeight calls FeeDistributor.accFeePerWeight() → uint256.
func feeDistributorAccFeePerWeight(ctx context.Context, client *ethclient.Client, feeDistAddr common.Address) (*big.Int, error) {
	// selector: keccak256("accFeePerWeight()") = 0x88b18b4c
	data := common.Hex2Bytes("88b18b4c")
	return callUint256(ctx, client, feeDistAddr, data)
}

// callUint256 performs a static call and decodes the returned 32-byte word as uint256.
func callUint256(ctx context.Context, client *ethclient.Client, to common.Address, data []byte) (*big.Int, error) {
	out, err := callRaw(ctx, client, to, data)
	if err != nil {
		return nil, err
	}
	if len(out) < 32 {
		return nil, fmt.Errorf("call to %s: response too short (%d bytes)", to.Hex(), len(out))
	}
	return new(big.Int).SetBytes(out[:32]), nil
}

// callRaw executes a static eth_call and returns the raw output bytes.
func callRaw(ctx context.Context, client *ethclient.Client, to common.Address, data []byte) ([]byte, error) {
	msg := ethereum.CallMsg{
		To:   &to,
		Data: data,
	}
	return client.CallContract(ctx, msg, nil)
}

// weiToEthString converts a *big.Int in wei to a human-readable ETH string
// with 18 decimal places (e.g. "1.500000000000000000").
func weiToEthString(wei *big.Int) string {
	if wei == nil {
		return "0"
	}
	ethUnit := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	whole := new(big.Int).Div(wei, ethUnit)
	frac := new(big.Int).Mod(wei, ethUnit)
	if frac.Sign() == 0 {
		return whole.String() + ".0"
	}
	fracStr := fmt.Sprintf("%018s", frac.String())
	// Trim trailing zeros for readability.
	trimmed := fracStr
	for len(trimmed) > 1 && trimmed[len(trimmed)-1] == '0' {
		trimmed = trimmed[:len(trimmed)-1]
	}
	return whole.String() + "." + trimmed
}

// zatToJunoString converts a zatoshi amount to a human-readable JUNO string (8 decimal places).
func zatToJunoString(zat int64) string {
	whole := zat / 1_0000_0000
	frac := zat % 1_0000_0000
	if frac < 0 {
		frac = -frac
	}
	if frac == 0 {
		return fmt.Sprintf("%d.0", whole)
	}
	fracStr := fmt.Sprintf("%08d", frac)
	trimmed := fracStr
	for len(trimmed) > 1 && trimmed[len(trimmed)-1] == '0' {
		trimmed = trimmed[:len(trimmed)-1]
	}
	return fmt.Sprintf("%d.%s", whole, trimmed)
}
