package tss

import (
	"encoding/hex"
	"errors"
	"strings"
)

const (
	SignRequestVersion  = "tss.sign.v1"
	SignResponseVersion = "tss.sign_result.v1"
	SignPathV1          = "/v1/sign"
)

var ErrInvalidSessionID = errors.New("tss: invalid session id")

type SignRequest struct {
	Version   string `json:"version"`
	SessionID string `json:"sessionId"`
	TxPlan    []byte `json:"txPlan"`
}

type SignResponse struct {
	Version   string `json:"version"`
	SessionID string `json:"sessionId"`
	SignedTx  []byte `json:"signedTx"`
}

func FormatSessionID(id [32]byte) string {
	return "0x" + hex.EncodeToString(id[:])
}

func ParseSessionID(s string) ([32]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if len(s) != 64 {
		return [32]byte{}, ErrInvalidSessionID
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, ErrInvalidSessionID
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

