package witnessitem

import (
	"encoding/binary"
	"testing"

	"github.com/juno-intents/intents-juno/internal/proverinput"
)

func TestEncodeDepositItem_Layout(t *testing.T) {
	t.Parallel()

	leafIndex := uint32(0x01020304)
	authPath := testAuthPath()
	action := testAction()

	got, err := EncodeDepositItem(leafIndex, authPath, action)
	if err != nil {
		t.Fatalf("EncodeDepositItem: %v", err)
	}
	if len(got) != proverinput.DepositWitnessItemLen {
		t.Fatalf("len mismatch: got=%d want=%d", len(got), proverinput.DepositWitnessItemLen)
	}

	if want := leafIndex; binary.LittleEndian.Uint32(got[:4]) != want {
		t.Fatalf("leaf index mismatch: got=%d want=%d", binary.LittleEndian.Uint32(got[:4]), want)
	}

	for i := 0; i < 32; i++ {
		off := 4 + (i * 32)
		if got[off] != byte(i+1) {
			t.Fatalf("auth_path[%d] mismatch at offset %d", i, off)
		}
	}

	base := 4 + (32 * 32)
	if got[base] != 0x11 { // nf
		t.Fatalf("nf mismatch")
	}
	if got[base+32] != 0x22 { // rk
		t.Fatalf("rk mismatch")
	}
	if got[base+64] != 0x33 { // cmx
		t.Fatalf("cmx mismatch")
	}
	if got[base+96] != 0x44 { // epk
		t.Fatalf("epk mismatch")
	}
	if got[base+128] != 0x55 { // enc
		t.Fatalf("enc mismatch")
	}
	if got[base+128+580] != 0x66 { // out
		t.Fatalf("out mismatch")
	}
	if got[len(got)-32] != 0x77 { // cv
		t.Fatalf("cv mismatch")
	}
}

func TestEncodeDepositItem_RejectsInvalidAuthPathLength(t *testing.T) {
	t.Parallel()

	authPath := testAuthPath()[:31]
	_, err := EncodeDepositItem(1, authPath, testAction())
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestEncodeWithdrawItem_Layout(t *testing.T) {
	t.Parallel()

	var withdrawalID [32]byte
	for i := range withdrawalID {
		withdrawalID[i] = 0x80 + byte(i)
	}
	var recipientRaw [43]byte
	for i := range recipientRaw {
		recipientRaw[i] = 0x40 + byte(i)
	}
	leafIndex := uint32(9)
	authPath := testAuthPath()
	action := testAction()

	got, err := EncodeWithdrawItem(withdrawalID, recipientRaw, leafIndex, authPath, action)
	if err != nil {
		t.Fatalf("EncodeWithdrawItem: %v", err)
	}
	if len(got) != proverinput.WithdrawWitnessItemLen {
		t.Fatalf("len mismatch: got=%d want=%d", len(got), proverinput.WithdrawWitnessItemLen)
	}
	if got[0] != 0x80 || got[31] != 0x9f {
		t.Fatalf("withdrawal id mismatch")
	}
	if got[32] != 0x40 || got[74] != 0x6a {
		t.Fatalf("recipient raw mismatch")
	}
	if got[75] != 9 || got[76] != 0 || got[77] != 0 || got[78] != 0 {
		t.Fatalf("leaf index encoding mismatch")
	}
}

func TestEncodeWithdrawItem_RejectsInvalidAuthPathLength(t *testing.T) {
	t.Parallel()

	var withdrawalID [32]byte
	var recipientRaw [43]byte
	_, err := EncodeWithdrawItem(withdrawalID, recipientRaw, 1, testAuthPath()[:30], testAction())
	if err == nil {
		t.Fatalf("expected error")
	}
}

func testAuthPath() [][32]byte {
	out := make([][32]byte, 32)
	for i := range out {
		out[i][0] = byte(i + 1)
	}
	return out
}

func testAction() OrchardAction {
	var a OrchardAction
	a.Nullifier[0] = 0x11
	a.RK[0] = 0x22
	a.CMX[0] = 0x33
	a.EphemeralKey[0] = 0x44
	a.EncCiphertext[0] = 0x55
	a.OutCiphertext[0] = 0x66
	a.CV[0] = 0x77
	return a
}
