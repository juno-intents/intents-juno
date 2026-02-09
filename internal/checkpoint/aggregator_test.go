package checkpoint

import (
	"bytes"
	"crypto/ecdsa"
	"sort"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func mustKey(t *testing.T, hexKey string) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		t.Fatalf("HexToECDSA(%s): %v", hexKey, err)
	}
	return k
}

func TestAggregator_EmitsPackageAtThreshold_SortedUnique(t *testing.T) {
	t.Parallel()

	k1 := mustKey(t, "4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	k2 := mustKey(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	k3 := mustKey(t, "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")

	op1 := crypto.PubkeyToAddress(k1.PublicKey)
	op2 := crypto.PubkeyToAddress(k2.PublicKey)
	op3 := crypto.PubkeyToAddress(k3.PublicKey)

	cp := Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := Digest(cp)

	sig1, err := SignDigest(k1, digest)
	if err != nil {
		t.Fatalf("SignDigest(k1): %v", err)
	}
	sig2, err := SignDigest(k2, digest)
	if err != nil {
		t.Fatalf("SignDigest(k2): %v", err)
	}
	sig3, err := SignDigest(k3, digest)
	if err != nil {
		t.Fatalf("SignDigest(k3): %v", err)
	}

	a, err := NewAggregator(AggregatorConfig{
		BaseChainID:    cp.BaseChainID,
		BridgeContract: cp.BridgeContract,
		Operators:      []common.Address{op1, op2, op3},
		Threshold:      3,
		Now:            time.Now,
	})
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}

	// Add signatures out of order to ensure sorting occurs in output.
	if pkg, ok, err := a.AddSignature(SignatureMessageV1{
		Operator:   op2,
		Digest:     digest,
		Signature:  sig2,
		Checkpoint: cp,
		SignedAt:   time.Unix(0, 0),
	}); err != nil || ok || pkg != nil {
		t.Fatalf("AddSignature(sig2): pkg=%v ok=%v err=%v", pkg, ok, err)
	}
	if pkg, ok, err := a.AddSignature(SignatureMessageV1{
		Operator:   op1,
		Digest:     digest,
		Signature:  sig1,
		Checkpoint: cp,
		SignedAt:   time.Unix(0, 0),
	}); err != nil || ok || pkg != nil {
		t.Fatalf("AddSignature(sig1): pkg=%v ok=%v err=%v", pkg, ok, err)
	}

	pkg, ok, err := a.AddSignature(SignatureMessageV1{
		Operator:   op3,
		Digest:     digest,
		Signature:  sig3,
		Checkpoint: cp,
		SignedAt:   time.Unix(0, 0),
	})
	if err != nil {
		t.Fatalf("AddSignature(sig3): %v", err)
	}
	if !ok || pkg == nil {
		t.Fatalf("expected package to be emitted")
	}
	if pkg.Digest != digest {
		t.Fatalf("digest mismatch: got %s want %s", pkg.Digest, digest)
	}
	if pkg.Checkpoint != cp {
		t.Fatalf("checkpoint mismatch")
	}
	if len(pkg.Signers) != 3 || len(pkg.Signatures) != 3 {
		t.Fatalf("unexpected package size: signers=%d signatures=%d", len(pkg.Signers), len(pkg.Signatures))
	}

	wantSigners := []common.Address{op1, op2, op3}
	sort.Slice(wantSigners, func(i, j int) bool { return bytes.Compare(wantSigners[i].Bytes(), wantSigners[j].Bytes()) < 0 })
	for i := range wantSigners {
		if pkg.Signers[i] != wantSigners[i] {
			t.Fatalf("signer[%d] mismatch: got %s want %s", i, pkg.Signers[i], wantSigners[i])
		}
		gotSigner, err := RecoverSigner(pkg.Digest, pkg.Signatures[i])
		if err != nil {
			t.Fatalf("RecoverSigner(sig[%d]): %v", i, err)
		}
		if gotSigner != pkg.Signers[i] {
			t.Fatalf("signature[%d] recovers to %s want %s", i, gotSigner, pkg.Signers[i])
		}
	}

	// Duplicate messages for an emitted digest should not re-emit.
	if pkg2, ok2, err := a.AddSignature(SignatureMessageV1{
		Operator:   op1,
		Digest:     digest,
		Signature:  sig1,
		Checkpoint: cp,
		SignedAt:   time.Unix(0, 0),
	}); err != nil || ok2 || pkg2 != nil {
		t.Fatalf("expected no re-emit after already emitted: pkg=%v ok=%v err=%v", pkg2, ok2, err)
	}
}

func TestAggregator_RejectsBadSignature(t *testing.T) {
	t.Parallel()

	k1 := mustKey(t, "4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	op1 := crypto.PubkeyToAddress(k1.PublicKey)

	cp := Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := Digest(cp)

	sig, err := SignDigest(k1, digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	sig[10] ^= 0xFF

	a, err := NewAggregator(AggregatorConfig{
		BaseChainID:    cp.BaseChainID,
		BridgeContract: cp.BridgeContract,
		Operators:      []common.Address{op1},
		Threshold:      1,
		Now:            time.Now,
	})
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}

	if pkg, ok, err := a.AddSignature(SignatureMessageV1{
		Operator:   op1,
		Digest:     digest,
		Signature:  sig,
		Checkpoint: cp,
		SignedAt:   time.Unix(0, 0),
	}); err == nil || ok || pkg != nil {
		t.Fatalf("expected rejection for bad signature: pkg=%v ok=%v err=%v", pkg, ok, err)
	}
}

func TestAggregator_RejectsOperatorMismatch(t *testing.T) {
	t.Parallel()

	k1 := mustKey(t, "4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	k2 := mustKey(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")

	op1 := crypto.PubkeyToAddress(k1.PublicKey)
	op2 := crypto.PubkeyToAddress(k2.PublicKey)

	cp := Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := Digest(cp)

	sig1, err := SignDigest(k1, digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	a, err := NewAggregator(AggregatorConfig{
		BaseChainID:    cp.BaseChainID,
		BridgeContract: cp.BridgeContract,
		Operators:      []common.Address{op1, op2},
		Threshold:      1,
		Now:            time.Now,
	})
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}

	// Claim operator=op2, but signature is from op1.
	if pkg, ok, err := a.AddSignature(SignatureMessageV1{
		Operator:   op2,
		Digest:     digest,
		Signature:  sig1,
		Checkpoint: cp,
		SignedAt:   time.Unix(0, 0),
	}); err == nil || ok || pkg != nil {
		t.Fatalf("expected rejection for operator mismatch: pkg=%v ok=%v err=%v", pkg, ok, err)
	}
}

func TestNewAggregator_RejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	_, err := NewAggregator(AggregatorConfig{
		BaseChainID:    8453,
		BridgeContract: common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
		Operators:      []common.Address{},
		Threshold:      1,
		Now:            time.Now,
	})
	if err == nil {
		t.Fatalf("expected error for empty operators")
	}

	_, err = NewAggregator(AggregatorConfig{
		BaseChainID:    8453,
		BridgeContract: common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
		Operators:      []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")},
		Threshold:      2,
		Now:            time.Now,
	})
	if err == nil {
		t.Fatalf("expected error for threshold > operator count")
	}
}
