package tsshost

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/tss"
	"github.com/juno-intents/intents-juno/internal/withdraw"
	blake2b "github.com/minio/blake2b-simd"
)

const (
	verifierOrchardRawAddressLen = 43
	verifierZip316PaddingLen     = 16
	verifierOrchardTypeCode      = 3
	verifierBech32mConst         = 0x2bc830a3
	verifierF4JumbleLeftMax      = 64
	verifierF4JumbleMinLen       = 48
	verifierF4JumbleMaxLen       = 4_194_368
)

var (
	verifierBech32Charset   = []byte("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
	verifierBech32Generator = [5]uint32{
		0x3b6a57b2,
		0x26508e6d,
		0x1ea119fa,
		0x3d4233dd,
		0x2a1462b3,
	}
)

var ErrRejected = errors.New("tsshost: rejected sign request")

type withdrawBatchReader interface {
	GetBatch(ctx context.Context, batchID [32]byte) (withdraw.Batch, error)
	GetWithdrawal(ctx context.Context, id [32]byte) (withdraw.Withdrawal, error)
}

type withdrawBatchVerifier struct {
	store withdrawBatchReader
	cfg   WithdrawBatchVerifierConfig
}

type WithdrawBatchVerifierConfig struct {
	BaseChainID   uint32
	BridgeAddress common.Address
}

func NewWithdrawBatchVerifier(store withdrawBatchReader, cfg WithdrawBatchVerifierConfig) Verifier {
	if store == nil {
		return nil
	}
	return &withdrawBatchVerifier{store: store, cfg: cfg}
}

func (v *withdrawBatchVerifier) VerifySignRequest(ctx context.Context, sessionID [32]byte, batchID [32]byte, txPlan []byte) error {
	if v == nil || v.store == nil {
		return nil
	}
	batch, err := v.store.GetBatch(ctx, batchID)
	if err != nil {
		if errors.Is(err, withdraw.ErrNotFound) {
			return fmt.Errorf("%w: batch not found", ErrRejected)
		}
		return err
	}
	if !isSignableBatchState(batch.State) {
		return fmt.Errorf("%w: batch state %s is not signable", ErrRejected, batch.State)
	}
	if len(batch.WithdrawalIDs) == 0 {
		return fmt.Errorf("%w: batch has no withdrawal ids", ErrRejected)
	}
	if !bytes.Equal(batch.TxPlan, txPlan) {
		return fmt.Errorf("%w: tx plan does not match persisted batch", ErrRejected)
	}
	expectedSessionID := tss.DeriveSigningSessionID(batchID, txPlan)
	if sessionID != expectedSessionID {
		return fmt.Errorf("%w: session id does not match batch binding", ErrRejected)
	}
	withdrawals := make([]withdraw.Withdrawal, 0, len(batch.WithdrawalIDs))
	for _, withdrawalID := range batch.WithdrawalIDs {
		w, err := v.store.GetWithdrawal(ctx, withdrawalID)
		if err != nil {
			if errors.Is(err, withdraw.ErrNotFound) {
				return fmt.Errorf("%w: withdrawal %x missing from persisted batch", ErrRejected, withdrawalID[:4])
			}
			return err
		}
		withdrawals = append(withdrawals, w)
	}
	if err := v.verifyOutputs(batchID, txPlan, withdrawals); err != nil {
		return err
	}
	return nil
}

type verifierTxPlan struct {
	Kind          string                 `json:"kind"`
	ChangeAddress string                 `json:"change_address"`
	Outputs       []verifierTxPlanOutput `json:"outputs"`
}

type verifierTxPlanOutput struct {
	ToAddress string `json:"to_address"`
	AmountZat string `json:"amount_zat"`
	MemoHex   string `json:"memo_hex,omitempty"`
}

func (v *withdrawBatchVerifier) verifyOutputs(batchID [32]byte, txPlan []byte, withdrawals []withdraw.Withdrawal) error {
	if v.cfg.BaseChainID == 0 {
		return fmt.Errorf("%w: missing verifier base chain id", ErrRejected)
	}
	if v.cfg.BridgeAddress == (common.Address{}) {
		return fmt.Errorf("%w: missing verifier bridge address", ErrRejected)
	}

	var plan verifierTxPlan
	if err := json.Unmarshal(txPlan, &plan); err != nil {
		return fmt.Errorf("%w: tx plan is not valid json", ErrRejected)
	}
	if strings.TrimSpace(plan.ChangeAddress) == "" {
		return fmt.Errorf("%w: tx plan missing change_address", ErrRejected)
	}
	recipientHRP, err := verifierBech32HRPFromAddress(plan.ChangeAddress)
	if err != nil {
		return fmt.Errorf("%w: invalid change_address", ErrRejected)
	}
	if len(plan.Outputs) != len(withdrawals) {
		return fmt.Errorf("%w: output count mismatch", ErrRejected)
	}

	var bridge20 [20]byte
	copy(bridge20[:], v.cfg.BridgeAddress[:])
	for idx, w := range withdrawals {
		expectedRecipient, err := verifierParseRecipientAddress(w.RecipientUA, recipientHRP)
		if err != nil {
			return fmt.Errorf("%w: invalid withdrawal recipient", ErrRejected)
		}
		_, net, err := withdraw.ComputeFeeAndNet(w.Amount, w.FeeBps)
		if err != nil {
			return fmt.Errorf("%w: invalid withdrawal amount", ErrRejected)
		}
		expectedMemo := memo.WithdrawalMemoV1{
			BaseChainID:  v.cfg.BaseChainID,
			BridgeAddr:   bridge20,
			WithdrawalID: w.ID,
			BatchID:      batchID,
		}.Encode()
		output := plan.Outputs[idx]
		if output.ToAddress != expectedRecipient {
			return fmt.Errorf("%w: output recipient mismatch", ErrRejected)
		}
		if output.AmountZat != strconv.FormatUint(net, 10) {
			return fmt.Errorf("%w: output amount mismatch", ErrRejected)
		}
		if !strings.EqualFold(strings.TrimSpace(output.MemoHex), hex.EncodeToString(expectedMemo[:])) {
			return fmt.Errorf("%w: output memo mismatch", ErrRejected)
		}
	}
	return nil
}

func isSignableBatchState(state withdraw.BatchState) bool {
	switch state {
	case withdraw.BatchStatePlanned, withdraw.BatchStateSigning, withdraw.BatchStateSigned:
		return true
	default:
		return false
	}
}

func verifierParseRecipientAddress(recipientUA []byte, recipientHRP string) (string, error) {
	if len(recipientUA) == 0 {
		return "", fmt.Errorf("empty recipient ua")
	}
	if len(recipientUA) == verifierOrchardRawAddressLen {
		encoded, err := verifierEncodeOrchardRawUnifiedAddress(recipientUA, recipientHRP)
		if err == nil {
			return encoded, nil
		}
	}
	recipient := string(recipientUA)
	if recipient != strings.TrimSpace(recipient) {
		return "", fmt.Errorf("recipient ua has leading/trailing whitespace")
	}
	return recipient, nil
}

func verifierBech32HRPFromAddress(address string) (string, error) {
	addr := strings.TrimSpace(address)
	if addr == "" {
		return "", fmt.Errorf("empty address")
	}
	if strings.ToLower(addr) != addr {
		return "", fmt.Errorf("address must be lowercase")
	}
	sep := strings.LastIndexByte(addr, '1')
	if sep <= 0 || sep+7 > len(addr) {
		return "", fmt.Errorf("invalid bech32m separator/length")
	}
	hrp := addr[:sep]
	if len(hrp) > verifierZip316PaddingLen {
		return "", fmt.Errorf("invalid hrp length")
	}
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", fmt.Errorf("invalid hrp")
		}
	}
	return hrp, nil
}

func verifierEncodeOrchardRawUnifiedAddress(recipientRaw []byte, hrp string) (string, error) {
	if len(recipientRaw) != verifierOrchardRawAddressLen {
		return "", fmt.Errorf("orchard receiver must be %d bytes", verifierOrchardRawAddressLen)
	}
	if hrp == "" {
		return "", fmt.Errorf("empty hrp")
	}
	if strings.ToLower(hrp) != hrp {
		return "", fmt.Errorf("hrp must be lowercase")
	}
	tlv := make([]byte, 0, 1+1+len(recipientRaw))
	tlv = verifierAppendCompactSize(tlv, verifierOrchardTypeCode)
	tlv = verifierAppendCompactSize(tlv, uint64(len(recipientRaw)))
	tlv = append(tlv, recipientRaw...)

	msg := make([]byte, len(tlv)+verifierZip316PaddingLen)
	copy(msg, tlv)
	copy(msg[len(tlv):], []byte(hrp))
	if err := verifierF4JumbleMut(msg); err != nil {
		return "", err
	}
	fiveBit, err := verifierConvertBits(msg, 8, 5, true)
	if err != nil {
		return "", err
	}
	checksum := verifierBech32Checksum(hrp, fiveBit)
	data := append(fiveBit, checksum...)
	var out strings.Builder
	out.Grow(len(hrp) + 1 + len(data))
	out.WriteString(hrp)
	out.WriteByte('1')
	for _, v := range data {
		out.WriteByte(verifierBech32Charset[v])
	}
	return out.String(), nil
}

func verifierAppendCompactSize(dst []byte, v uint64) []byte {
	switch {
	case v <= 252:
		return append(dst, byte(v))
	case v <= 0xffff:
		return append(dst, 0xfd, byte(v), byte(v>>8))
	case v <= 0xffffffff:
		return append(dst, 0xfe, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	default:
		return append(dst, 0xff,
			byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
			byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56),
		)
	}
}

func verifierConvertBits(data []byte, fromBits uint, toBits uint, pad bool) ([]byte, error) {
	acc := uint(0)
	bits := uint(0)
	maxv := uint((1 << toBits) - 1)
	maxAcc := uint((1 << (fromBits + toBits - 1)) - 1)
	out := make([]byte, 0, (len(data)*int(fromBits)+int(toBits)-1)/int(toBits))
	for _, value := range data {
		v := uint(value)
		if v>>(fromBits) != 0 {
			return nil, fmt.Errorf("invalid data range")
		}
		acc = ((acc << fromBits) | v) & maxAcc
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, fmt.Errorf("non-zero padding")
	}
	return out, nil
}

func verifierBech32Checksum(hrp string, data []byte) []byte {
	values := make([]byte, 0, len(hrp)*2+1+len(data)+6)
	values = append(values, verifierBech32HRPExpand(hrp)...)
	values = append(values, data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := verifierBech32Polymod(values) ^ verifierBech32mConst
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = byte((mod >> uint(5*(5-i))) & 31)
	}
	return out
}

func verifierBech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func verifierBech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if ((top >> uint(i)) & 1) != 0 {
				chk ^= verifierBech32Generator[i]
			}
		}
	}
	return chk
}

func verifierF4JumbleMut(message []byte) error {
	if len(message) < verifierF4JumbleMinLen || len(message) > verifierF4JumbleMaxLen {
		return fmt.Errorf("invalid f4jumble length")
	}
	leftLen := len(message) / 2
	if leftLen > verifierF4JumbleLeftMax {
		leftLen = verifierF4JumbleLeftMax
	}
	left := message[:leftLen]
	right := message[leftLen:]
	if err := verifierF4GRound(left, right, 0); err != nil {
		return err
	}
	if err := verifierF4HRound(left, right, 0); err != nil {
		return err
	}
	if err := verifierF4GRound(left, right, 1); err != nil {
		return err
	}
	return verifierF4HRound(left, right, 1)
}

func verifierF4HRound(left []byte, right []byte, round byte) error {
	personal := [16]byte{'U', 'A', '_', 'F', '4', 'J', 'u', 'm', 'b', 'l', 'e', '_', 'H', round, 0, 0}
	h, err := blake2b.New(&blake2b.Config{
		Size:   uint8(len(left)),
		Person: personal[:],
	})
	if err != nil {
		return err
	}
	if _, err := h.Write(right); err != nil {
		return err
	}
	sum := h.Sum(nil)
	for i := range left {
		left[i] ^= sum[i]
	}
	return nil
}

func verifierF4GRound(left []byte, right []byte, round byte) error {
	const outBytes = 64
	chunks := (len(right) + outBytes - 1) / outBytes
	for j := 0; j < chunks; j++ {
		personal := [16]byte{'U', 'A', '_', 'F', '4', 'J', 'u', 'm', 'b', 'l', 'e', '_', 'G', round, byte(j), byte(j >> 8)}
		h, err := blake2b.New(&blake2b.Config{
			Size:   outBytes,
			Person: personal[:],
		})
		if err != nil {
			return err
		}
		if _, err := h.Write(left); err != nil {
			return err
		}
		sum := h.Sum(nil)
		start := j * outBytes
		end := start + outBytes
		if end > len(right) {
			end = len(right)
		}
		for k := start; k < end; k++ {
			right[k] ^= sum[k-start]
		}
	}
	return nil
}
