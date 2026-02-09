package eth

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestLocalSigner_SignsDynamicFeeTx(t *testing.T) {
	chainID := big.NewInt(8453)

	// Fixed dev key.
	key, err := crypto.HexToECDSA("4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}

	s := NewLocalSigner(key)
	if (s.Address() == common.Address{}) {
		t.Fatalf("expected non-zero address")
	}

	to := common.HexToAddress("0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1")
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     7,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(2),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(0),
	})

	signed, err := s.SignTx(tx, chainID)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}

	signer := types.LatestSignerForChainID(chainID)
	from, err := types.Sender(signer, signed)
	if err != nil {
		t.Fatalf("Sender: %v", err)
	}
	if from != s.Address() {
		t.Fatalf("from mismatch: got %s want %s", from, s.Address())
	}
}
