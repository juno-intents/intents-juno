package tss

import (
	"crypto/sha256"
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
var ErrInvalidBatchID = errors.New("tss: invalid batch id")

type SignRequest struct {
	Version   string `json:"version"`
	SessionID string `json:"sessionId"`
	BatchID   string `json:"batchId"`
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
	return parseID32(s, ErrInvalidSessionID)
}

func FormatBatchID(id [32]byte) string {
	return "0x" + hex.EncodeToString(id[:])
}

func ParseBatchID(s string) ([32]byte, error) {
	return parseID32(s, ErrInvalidBatchID)
}

func parseID32(s string, invalid error) ([32]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if len(s) != 64 {
		return [32]byte{}, invalid
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, invalid
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

func DeriveSigningSessionID(batchID [32]byte, txPlan []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("withdraw-sign-session-v1"))
	_, _ = h.Write(batchID[:])
	_, _ = h.Write(txPlan)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
