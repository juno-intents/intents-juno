package checkpoint

import (
	"errors"
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestQuorumVerifier_VerifyCheckpointSignatures(t *testing.T) {
	t.Parallel()

	k1, err := crypto.HexToECDSA("4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	if err != nil {
		t.Fatalf("HexToECDSA k1: %v", err)
	}
	k2, err := crypto.HexToECDSA("6c875d0e7f3d0d840e4f1a400a54c3c4d5ef0e8f55d8aee0b1b1f0c0a8f6c1d1")
	if err != nil {
		t.Fatalf("HexToECDSA k2: %v", err)
	}
	k3, err := crypto.HexToECDSA("7a6c875d0e7f3d0d840e4f1a400a54c3c4d5ef0e8f55d8aee0b1b1f0c0a8f6c1")
	if err != nil {
		t.Fatalf("HexToECDSA k3: %v", err)
	}

	a1 := crypto.PubkeyToAddress(k1.PublicKey)
	a2 := crypto.PubkeyToAddress(k2.PublicKey)
	a3 := crypto.PubkeyToAddress(k3.PublicKey)
	ops := []common.Address{a1, a2, a3}
	slices.SortFunc(ops, func(a, b common.Address) int {
		return slices.Compare(a[:], b[:])
	})

	v, err := NewQuorumVerifier(ops, 2)
	if err != nil {
		t.Fatalf("NewQuorumVerifier: %v", err)
	}

	cp := Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	d := Digest(cp)

	sig1, err := SignDigest(k1, d)
	if err != nil {
		t.Fatalf("SignDigest(k1): %v", err)
	}
	sig2, err := SignDigest(k2, d)
	if err != nil {
		t.Fatalf("SignDigest(k2): %v", err)
	}

	type pair struct {
		addr common.Address
		sig  []byte
	}
	pairs := []pair{{a1, sig1}, {a2, sig2}}
	slices.SortFunc(pairs, func(a, b pair) int {
		return slices.Compare(a.addr[:], b.addr[:])
	})

	sigs := [][]byte{pairs[0].sig, pairs[1].sig}
	signers, err := v.VerifyCheckpointSignatures(cp, sigs)
	if err != nil {
		t.Fatalf("VerifyCheckpointSignatures: %v", err)
	}
	if len(signers) != 2 {
		t.Fatalf("signers len: got %d want 2", len(signers))
	}
}

func TestQuorumVerifier_RejectsUnsortedSignatures(t *testing.T) {
	t.Parallel()

	k1, _ := crypto.HexToECDSA("4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	k2, _ := crypto.HexToECDSA("6c875d0e7f3d0d840e4f1a400a54c3c4d5ef0e8f55d8aee0b1b1f0c0a8f6c1d1")
	a1 := crypto.PubkeyToAddress(k1.PublicKey)
	a2 := crypto.PubkeyToAddress(k2.PublicKey)
	v, err := NewQuorumVerifier([]common.Address{a1, a2}, 2)
	if err != nil {
		t.Fatalf("NewQuorumVerifier: %v", err)
	}

	cp := Checkpoint{
		Height:           1,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	d := Digest(cp)
	sig1, _ := SignDigest(k1, d)
	sig2, _ := SignDigest(k2, d)

	type pair struct {
		addr common.Address
		sig  []byte
	}
	pairs := []pair{{a1, sig1}, {a2, sig2}}
	slices.SortFunc(pairs, func(a, b pair) int {
		return slices.Compare(a.addr[:], b.addr[:])
	})

	// Intentionally pass signatures in descending signer order.
	_, err = v.VerifyCheckpointSignatures(cp, [][]byte{pairs[1].sig, pairs[0].sig})
	if !errors.Is(err, ErrUnsortedSignatures) {
		t.Fatalf("expected ErrUnsortedSignatures, got %v", err)
	}
}

func TestParseOperatorAddressesCSV(t *testing.T) {
	t.Parallel()

	ops, err := ParseOperatorAddressesCSV("0x1111111111111111111111111111111111111111, 0x2222222222222222222222222222222222222222")
	if err != nil {
		t.Fatalf("ParseOperatorAddressesCSV: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("len: got %d want 2", len(ops))
	}
}
