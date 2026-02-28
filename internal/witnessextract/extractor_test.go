package witnessextract

import (
	"context"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/junorpc"
	"github.com/juno-intents/intents-juno/internal/proverinput"
)

func TestBuilder_BuildDeposit_Success(t *testing.T) {
	t.Parallel()

	scan := &stubScan{
		notes: []WalletNote{
			{
				TxID:        "39abd5a44a45b46c913e3d5ed1da22b25f08db8b9c3e52a3dbc9f4e23944998e",
				ActionIndex: 2,
				Position:    ptrInt64(7),
			},
		},
		witness: WitnessResponse{
			Root: "0x" + strings.Repeat("99", 32),
			Paths: []WitnessPath{
				{
					Position: 7,
					AuthPath: testAuthPathHex(),
				},
			},
		},
	}
	rpc := &stubRPC{
		action: testRPCAction(),
	}

	b := New(scan, rpc)
	got, err := b.BuildDeposit(context.Background(), DepositRequest{
		WalletID:    "wallet-a",
		TxID:        scan.notes[0].TxID,
		ActionIndex: 2,
	})
	if err != nil {
		t.Fatalf("BuildDeposit: %v", err)
	}
	if got.FinalOrchardRoot != common.HexToHash(scan.witness.Root) {
		t.Fatalf("root mismatch: got=%s want=%s", got.FinalOrchardRoot.Hex(), common.HexToHash(scan.witness.Root).Hex())
	}
	if got.Position != 7 {
		t.Fatalf("position mismatch: got=%d want=7", got.Position)
	}
	if len(got.WitnessItem) != proverinput.DepositWitnessItemLen {
		t.Fatalf("witness len mismatch: got=%d want=%d", len(got.WitnessItem), proverinput.DepositWitnessItemLen)
	}
}

func TestBuilder_BuildDeposit_NoteNotFound(t *testing.T) {
	t.Parallel()

	b := New(&stubScan{}, &stubRPC{})
	_, err := b.BuildDeposit(context.Background(), DepositRequest{
		WalletID:    "wallet-a",
		TxID:        "39abd5a44a45b46c913e3d5ed1da22b25f08db8b9c3e52a3dbc9f4e23944998e",
		ActionIndex: 0,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "note not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuilder_BuildWithdraw_Success(t *testing.T) {
	t.Parallel()

	scan := &stubScan{
		notes: []WalletNote{
			{
				TxID:        "39abd5a44a45b46c913e3d5ed1da22b25f08db8b9c3e52a3dbc9f4e23944998e",
				ActionIndex: 1,
				Position:    ptrInt64(3),
			},
		},
		witness: WitnessResponse{
			Root: "0x" + strings.Repeat("88", 32),
			Paths: []WitnessPath{
				{
					Position: 3,
					AuthPath: testAuthPathHex(),
				},
			},
		},
	}
	rpc := &stubRPC{
		action: testRPCAction(),
	}

	var withdrawalID [32]byte
	withdrawalID[0] = 0xaa
	var recipientRaw [43]byte
	recipientRaw[0] = 0xbb

	b := New(scan, rpc)
	got, err := b.BuildWithdraw(context.Background(), WithdrawRequest{
		WalletID:            "wallet-b",
		TxID:                scan.notes[0].TxID,
		ActionIndex:         1,
		WithdrawalID:        withdrawalID,
		RecipientRawAddress: recipientRaw,
	})
	if err != nil {
		t.Fatalf("BuildWithdraw: %v", err)
	}
	if got.FinalOrchardRoot != common.HexToHash(scan.witness.Root) {
		t.Fatalf("root mismatch: got=%s want=%s", got.FinalOrchardRoot.Hex(), common.HexToHash(scan.witness.Root).Hex())
	}
	if got.Position != 3 {
		t.Fatalf("position mismatch: got=%d want=3", got.Position)
	}
	if len(got.WitnessItem) != proverinput.WithdrawWitnessItemLen {
		t.Fatalf("witness len mismatch: got=%d want=%d", len(got.WitnessItem), proverinput.WithdrawWitnessItemLen)
	}
	if rpc.gotActionIndex != 1 {
		t.Fatalf("rpc action index mismatch: got=%d want=1", rpc.gotActionIndex)
	}
}

func TestBuilder_BuildWithdraw_FallbackActionIndexByExpectedValue(t *testing.T) {
	t.Parallel()

	expectedValue := uint64(9900)
	scan := &stubScan{
		notes: []WalletNote{
			{
				TxID:        "39abd5a44a45b46c913e3d5ed1da22b25f08db8b9c3e52a3dbc9f4e23944998e",
				ActionIndex: 0,
				Position:    ptrInt64(2),
				ValueZat:    2500000,
			},
			{
				TxID:        "39abd5a44a45b46c913e3d5ed1da22b25f08db8b9c3e52a3dbc9f4e23944998e",
				ActionIndex: 1,
				Position:    ptrInt64(3),
				ValueZat:    expectedValue,
			},
		},
		witness: WitnessResponse{
			Root: "0x" + strings.Repeat("88", 32),
			Paths: []WitnessPath{
				{
					Position: 3,
					AuthPath: testAuthPathHex(),
				},
			},
		},
	}
	rpc := &stubRPC{
		action: testRPCAction(),
	}

	var withdrawalID [32]byte
	withdrawalID[0] = 0xaa
	var recipientRaw [43]byte
	recipientRaw[0] = 0xbb

	b := New(scan, rpc)
	got, err := b.BuildWithdraw(context.Background(), WithdrawRequest{
		WalletID:            "wallet-b",
		TxID:                scan.notes[0].TxID,
		ActionIndex:         0,
		ExpectedValueZat:    &expectedValue,
		WithdrawalID:        withdrawalID,
		RecipientRawAddress: recipientRaw,
	})
	if err != nil {
		t.Fatalf("BuildWithdraw: %v", err)
	}
	if got.Position != 3 {
		t.Fatalf("position mismatch: got=%d want=3", got.Position)
	}
	if rpc.gotActionIndex != 1 {
		t.Fatalf("rpc action index mismatch: got=%d want=1", rpc.gotActionIndex)
	}
}

func TestBuilder_BuildWithdraw_FallbackWalletIDByTxMatch(t *testing.T) {
	t.Parallel()

	expectedValue := uint64(9900)
	txID := "39abd5a44a45b46c913e3d5ed1da22b25f08db8b9c3e52a3dbc9f4e23944998e"
	scan := &stubScan{
		notesByWallet: map[string][]WalletNote{
			"wallet-primary": {
				{
					TxID:        "d6c6553769ba6b20cd27fb8f57f5f661e7dce6d55a07c31f65ec47bd558f95ba",
					ActionIndex: 0,
					Position:    ptrInt64(9),
				},
			},
			"wallet-indexed": {
				{
					TxID:        txID,
					ActionIndex: 1,
					Position:    ptrInt64(3),
					ValueZat:    expectedValue,
				},
			},
		},
		walletIDs: []string{"wallet-primary", "wallet-indexed"},
		witness: WitnessResponse{
			Root: "0x" + strings.Repeat("88", 32),
			Paths: []WitnessPath{
				{
					Position: 3,
					AuthPath: testAuthPathHex(),
				},
			},
		},
	}
	rpc := &stubRPC{
		action: testRPCAction(),
	}

	var withdrawalID [32]byte
	withdrawalID[0] = 0xaa
	var recipientRaw [43]byte
	recipientRaw[0] = 0xbb

	b := New(scan, rpc)
	got, err := b.BuildWithdraw(context.Background(), WithdrawRequest{
		WalletID:            "wallet-primary",
		TxID:                txID,
		ActionIndex:         0,
		ExpectedValueZat:    &expectedValue,
		WithdrawalID:        withdrawalID,
		RecipientRawAddress: recipientRaw,
	})
	if err != nil {
		t.Fatalf("BuildWithdraw: %v", err)
	}
	if got.Position != 3 {
		t.Fatalf("position mismatch: got=%d want=3", got.Position)
	}
	if rpc.gotActionIndex != 1 {
		t.Fatalf("rpc action index mismatch: got=%d want=1", rpc.gotActionIndex)
	}
}

type stubScan struct {
	notes         []WalletNote
	notesByWallet map[string][]WalletNote
	walletIDs     []string
	witness       WitnessResponse
	err           error
}

func (s *stubScan) ListWalletIDs(ctx context.Context) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	if len(s.walletIDs) > 0 {
		return append([]string(nil), s.walletIDs...), nil
	}
	if len(s.notesByWallet) > 0 {
		out := make([]string, 0, len(s.notesByWallet))
		for walletID := range s.notesByWallet {
			out = append(out, walletID)
		}
		return out, nil
	}
	return []string{"wallet-default"}, nil
}

func (s *stubScan) ListWalletNotes(ctx context.Context, walletID string) ([]WalletNote, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.notesByWallet != nil {
		return append([]WalletNote(nil), s.notesByWallet[walletID]...), nil
	}
	return append([]WalletNote(nil), s.notes...), nil
}

func (s *stubScan) OrchardWitness(ctx context.Context, anchorHeight *int64, positions []uint32) (WitnessResponse, error) {
	if s.err != nil {
		return WitnessResponse{}, s.err
	}
	return s.witness, nil
}

type stubRPC struct {
	action         junorpc.OrchardAction
	err            error
	gotTxID        string
	gotActionIndex uint32
}

func (s *stubRPC) GetOrchardAction(ctx context.Context, txid string, actionIndex uint32) (junorpc.OrchardAction, error) {
	s.gotTxID = txid
	s.gotActionIndex = actionIndex
	if s.err != nil {
		return junorpc.OrchardAction{}, s.err
	}
	return s.action, nil
}

func testRPCAction() junorpc.OrchardAction {
	var out junorpc.OrchardAction
	out.Nullifier[0] = 0x01
	out.RK[0] = 0x02
	out.CMX[0] = 0x03
	out.EphemeralKey[0] = 0x04
	out.EncCiphertext[0] = 0x05
	out.OutCiphertext[0] = 0x06
	out.CV[0] = 0x07
	return out
}

func testAuthPathHex() []string {
	out := make([]string, 32)
	for i := 0; i < 32; i++ {
		b := make([]byte, 32)
		b[0] = byte(i + 1)
		out[i] = "0x" + common.Bytes2Hex(b)
	}
	return out
}

func ptrInt64(v int64) *int64 {
	return &v
}
