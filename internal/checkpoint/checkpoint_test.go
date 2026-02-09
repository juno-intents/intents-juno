package checkpoint

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestDigest_GoldenVectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cp   Checkpoint
		want common.Hash
	}{
		{
			name: "base-mainnet-example",
			cp: Checkpoint{
				Height:           123,
				BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
				FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
				BaseChainID:      8453,
				BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
			},
			// Computed with Foundry cast (EIP-712, OZ EIP712(name="WJUNO Bridge", version="1")).
			want: common.HexToHash("0x688fcd90cce56cb44480c50331d4d35fe77bc15b43cffe150042570c49692e4a"),
		},
		{
			name: "anvil-example",
			cp: Checkpoint{
				Height:           0,
				BlockHash:        common.HexToHash("0x39abd5a44a45b46c913e3d5ed1da22b25f08db8b9c3e52a3dbc9f4e23944998e"),
				FinalOrchardRoot: common.HexToHash("0xd0f97deef4210a7792e4aea037a03e079d3b95b5e23da221752f0d1f54ab6b54"),
				BaseChainID:      31337,
				BridgeContract:   common.HexToAddress("0x1111111111111111111111111111111111111111"),
			},
			want: common.HexToHash("0xd01727b2a01ccd4aa9a43b270fa6ebe68bf9622336ad0f6a6a0898ffe91be5fe"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Digest(tt.cp)
			if got != tt.want {
				t.Fatalf("Digest mismatch:\n got  %s\n want %s", got, tt.want)
			}
		})
	}
}

func TestSignAndRecover(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}
	wantAddr := crypto.PubkeyToAddress(key.PublicKey)

	cp := Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := Digest(cp)

	sig, err := SignDigest(key, digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("signature length: got %d want 65", len(sig))
	}
	if sig[64] != 27 && sig[64] != 28 {
		t.Fatalf("signature v: got %d want 27/28", sig[64])
	}

	gotAddr, err := RecoverSigner(digest, sig)
	if err != nil {
		t.Fatalf("RecoverSigner: %v", err)
	}
	if gotAddr != wantAddr {
		t.Fatalf("recovered address mismatch: got %s want %s", gotAddr, wantAddr)
	}

	// Reject wrong digest.
	var otherDigest common.Hash
	copy(otherDigest[:], digest[:])
	otherDigest[0] ^= 0x01

	gotAddr2, err := RecoverSigner(otherDigest, sig)
	if err == nil && gotAddr2 == wantAddr {
		t.Fatalf("expected recover to fail for wrong digest")
	}
}

func TestRecoverSigner_RejectsBadSignatureLength(t *testing.T) {
	t.Parallel()

	digest := common.HexToHash("0x688fcd90cce56cb44480c50331d4d35fe77bc15b43cffe150042570c49692e4a")

	// 64-byte signature is EIP-2098 compact; not accepted by our off-chain format (Bridge expects 65).
	sig := make([]byte, 64)
	_, err := RecoverSigner(digest, sig)
	if err == nil {
		t.Fatalf("expected error")
	}
}
