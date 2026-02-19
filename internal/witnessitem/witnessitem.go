package witnessitem

import (
	"encoding/binary"
	"fmt"

	"github.com/juno-intents/intents-juno/internal/proverinput"
)

const authPathDepth = 32

type OrchardAction struct {
	Nullifier     [32]byte
	RK            [32]byte
	CMX           [32]byte
	EphemeralKey  [32]byte
	EncCiphertext [580]byte
	OutCiphertext [80]byte
	CV            [32]byte
}

func EncodeDepositItem(leafIndex uint32, authPath [][32]byte, action OrchardAction) ([]byte, error) {
	if len(authPath) != authPathDepth {
		return nil, fmt.Errorf("witnessitem: invalid auth_path length: got=%d want=%d", len(authPath), authPathDepth)
	}

	out := make([]byte, 0, proverinput.DepositWitnessItemLen)
	out = binary.LittleEndian.AppendUint32(out, leafIndex)
	for _, h := range authPath {
		out = append(out, h[:]...)
	}
	out = append(out, action.Nullifier[:]...)
	out = append(out, action.RK[:]...)
	out = append(out, action.CMX[:]...)
	out = append(out, action.EphemeralKey[:]...)
	out = append(out, action.EncCiphertext[:]...)
	out = append(out, action.OutCiphertext[:]...)
	out = append(out, action.CV[:]...)
	return out, nil
}

func EncodeWithdrawItem(
	withdrawalID [32]byte,
	recipientRawAddress [43]byte,
	leafIndex uint32,
	authPath [][32]byte,
	action OrchardAction,
) ([]byte, error) {
	if len(authPath) != authPathDepth {
		return nil, fmt.Errorf("witnessitem: invalid auth_path length: got=%d want=%d", len(authPath), authPathDepth)
	}

	out := make([]byte, 0, proverinput.WithdrawWitnessItemLen)
	out = append(out, withdrawalID[:]...)
	out = append(out, recipientRawAddress[:]...)
	out = binary.LittleEndian.AppendUint32(out, leafIndex)
	for _, h := range authPath {
		out = append(out, h[:]...)
	}
	out = append(out, action.Nullifier[:]...)
	out = append(out, action.RK[:]...)
	out = append(out, action.CMX[:]...)
	out = append(out, action.EphemeralKey[:]...)
	out = append(out, action.EncCiphertext[:]...)
	out = append(out, action.OutCiphertext[:]...)
	out = append(out, action.CV[:]...)
	return out, nil
}
