package memo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

const MemoLen = 512

var (
	ErrInvalidLength   = errors.New("memo: invalid length")
	ErrInvalidMagic    = errors.New("memo: invalid magic")
	ErrDomainMismatch  = errors.New("memo: domain mismatch")
	ErrInvalidChecksum = errors.New("memo: invalid checksum")
	ErrNonZeroPadding  = errors.New("memo: non-zero padding")
)

var (
	depositMagicV1    = [8]byte{'W', 'J', 'U', 'N', 'O', 0x01, 0x00, 0x00}
	withdrawalMagicV1 = [8]byte{'W', 'J', 'U', 'N', 'O', 'W', 'D', 0x01}
)

const (
	depositV1CRCOffset     = 64
	depositV1PaddingOffset = 68
)

const (
	withdrawalV1CRCOffset     = 100
	withdrawalV1PaddingOffset = 104
)

type DepositMemoV1 struct {
	BaseChainID   uint32
	BridgeAddr    [20]byte
	BaseRecipient [20]byte
	Nonce         uint64
	Flags         uint32
}

// Encode returns the canonical 512-byte DepositMemo v1 encoding.
//
// Spec (all integers big-endian):
//
//	MAGIC[8] = "WJUNO\x01\x00\x00"
//	baseChainId[4]
//	bridgeAddr[20]
//	baseRecipient[20]
//	nonce[8]
//	flags[4]
//	crc32[4] over everything above (IEEE)
//	padding[444] = zeros
func (m DepositMemoV1) Encode() [MemoLen]byte {
	var out [MemoLen]byte

	o := 0
	copy(out[o:o+8], depositMagicV1[:])
	o += 8
	binary.BigEndian.PutUint32(out[o:o+4], m.BaseChainID)
	o += 4
	copy(out[o:o+20], m.BridgeAddr[:])
	o += 20
	copy(out[o:o+20], m.BaseRecipient[:])
	o += 20
	binary.BigEndian.PutUint64(out[o:o+8], m.Nonce)
	o += 8
	binary.BigEndian.PutUint32(out[o:o+4], m.Flags)
	o += 4

	// CRC covers everything above (i.e., bytes [0:depositV1CRCOffset]).
	crc := crc32.ChecksumIEEE(out[:depositV1CRCOffset])
	binary.BigEndian.PutUint32(out[o:o+4], crc)

	// Remaining bytes are already zero.
	return out
}

// ParseDepositMemoV1 parses a 512-byte DepositMemo v1 and enforces domain separation
// by rejecting memos with a different baseChainId or bridgeAddr than expected.
func ParseDepositMemoV1(b []byte, expectedBaseChainID uint32, expectedBridgeAddr [20]byte) (DepositMemoV1, error) {
	if len(b) != MemoLen {
		return DepositMemoV1{}, fmt.Errorf("%w: got %d want %d", ErrInvalidLength, len(b), MemoLen)
	}

	if !matchMagic(b[:8], depositMagicV1) {
		return DepositMemoV1{}, fmt.Errorf("%w: deposit v1", ErrInvalidMagic)
	}

	wantCRC := binary.BigEndian.Uint32(b[depositV1CRCOffset : depositV1CRCOffset+4])
	haveCRC := crc32.ChecksumIEEE(b[:depositV1CRCOffset])
	if wantCRC != haveCRC {
		return DepositMemoV1{}, fmt.Errorf("%w: want 0x%08x have 0x%08x", ErrInvalidChecksum, wantCRC, haveCRC)
	}

	if !allZero(b[depositV1PaddingOffset:]) {
		return DepositMemoV1{}, fmt.Errorf("%w: deposit v1", ErrNonZeroPadding)
	}

	chainID := binary.BigEndian.Uint32(b[8:12])
	if chainID != expectedBaseChainID {
		return DepositMemoV1{}, fmt.Errorf("%w: baseChainId mismatch", ErrDomainMismatch)
	}

	var bridge [20]byte
	copy(bridge[:], b[12:32])
	if bridge != expectedBridgeAddr {
		return DepositMemoV1{}, fmt.Errorf("%w: bridgeAddr mismatch", ErrDomainMismatch)
	}

	var recipient [20]byte
	copy(recipient[:], b[32:52])
	nonce := binary.BigEndian.Uint64(b[52:60])
	flags := binary.BigEndian.Uint32(b[60:64])

	return DepositMemoV1{
		BaseChainID:   chainID,
		BridgeAddr:    bridge,
		BaseRecipient: recipient,
		Nonce:         nonce,
		Flags:         flags,
	}, nil
}

type WithdrawalMemoV1 struct {
	BaseChainID  uint32
	BridgeAddr   [20]byte
	WithdrawalID [32]byte
	BatchID      [32]byte
	Flags        uint32
}

// Encode returns the canonical 512-byte WithdrawalMemo v1 encoding.
//
// Spec (all integers big-endian):
//
//	MAGIC[8] = "WJUNOWD\x01"
//	baseChainId[4]
//	bridgeAddr[20]
//	withdrawalId[32]
//	batchId[32]
//	flags[4]
//	crc32[4] over everything above (IEEE)
//	padding[408] = zeros
func (m WithdrawalMemoV1) Encode() [MemoLen]byte {
	var out [MemoLen]byte

	o := 0
	copy(out[o:o+8], withdrawalMagicV1[:])
	o += 8
	binary.BigEndian.PutUint32(out[o:o+4], m.BaseChainID)
	o += 4
	copy(out[o:o+20], m.BridgeAddr[:])
	o += 20
	copy(out[o:o+32], m.WithdrawalID[:])
	o += 32
	copy(out[o:o+32], m.BatchID[:])
	o += 32
	binary.BigEndian.PutUint32(out[o:o+4], m.Flags)
	o += 4

	crc := crc32.ChecksumIEEE(out[:withdrawalV1CRCOffset])
	binary.BigEndian.PutUint32(out[o:o+4], crc)
	return out
}

// ParseWithdrawalMemoV1 parses a 512-byte WithdrawalMemo v1 and enforces domain separation
// by rejecting memos with a different baseChainId or bridgeAddr than expected.
func ParseWithdrawalMemoV1(b []byte, expectedBaseChainID uint32, expectedBridgeAddr [20]byte) (WithdrawalMemoV1, error) {
	if len(b) != MemoLen {
		return WithdrawalMemoV1{}, fmt.Errorf("%w: got %d want %d", ErrInvalidLength, len(b), MemoLen)
	}

	if !matchMagic(b[:8], withdrawalMagicV1) {
		return WithdrawalMemoV1{}, fmt.Errorf("%w: withdrawal v1", ErrInvalidMagic)
	}

	wantCRC := binary.BigEndian.Uint32(b[withdrawalV1CRCOffset : withdrawalV1CRCOffset+4])
	haveCRC := crc32.ChecksumIEEE(b[:withdrawalV1CRCOffset])
	if wantCRC != haveCRC {
		return WithdrawalMemoV1{}, fmt.Errorf("%w: want 0x%08x have 0x%08x", ErrInvalidChecksum, wantCRC, haveCRC)
	}

	if !allZero(b[withdrawalV1PaddingOffset:]) {
		return WithdrawalMemoV1{}, fmt.Errorf("%w: withdrawal v1", ErrNonZeroPadding)
	}

	chainID := binary.BigEndian.Uint32(b[8:12])
	if chainID != expectedBaseChainID {
		return WithdrawalMemoV1{}, fmt.Errorf("%w: baseChainId mismatch", ErrDomainMismatch)
	}

	var bridge [20]byte
	copy(bridge[:], b[12:32])
	if bridge != expectedBridgeAddr {
		return WithdrawalMemoV1{}, fmt.Errorf("%w: bridgeAddr mismatch", ErrDomainMismatch)
	}

	var withdrawalID [32]byte
	copy(withdrawalID[:], b[32:64])
	var batchID [32]byte
	copy(batchID[:], b[64:96])
	flags := binary.BigEndian.Uint32(b[96:100])

	return WithdrawalMemoV1{
		BaseChainID:  chainID,
		BridgeAddr:   bridge,
		WithdrawalID: withdrawalID,
		BatchID:      batchID,
		Flags:        flags,
	}, nil
}

func matchMagic(b []byte, want [8]byte) bool {
	if len(b) != 8 {
		return false
	}
	for i := 0; i < 8; i++ {
		if b[i] != want[i] {
			return false
		}
	}
	return true
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
