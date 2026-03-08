package bridgeapi

import (
	"fmt"
	"strings"

	blake2b "github.com/minio/blake2b-simd"
)

const (
	orchardRawAddressLen = 43
	zip316PaddingLen     = 16
	orchardTypeCode      = 3
	bech32mConst         = 0x2bc830a3
	f4jumbleLeftMax      = 64
	f4jumbleMinLen       = 48
	f4jumbleMaxLen       = 4_194_368
)

var (
	bech32Charset   = []byte("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
	bech32Generator = [5]uint32{
		0x3b6a57b2,
		0x26508e6d,
		0x1ea119fa,
		0x3d4233dd,
		0x2a1462b3,
	}
	// Reverse lookup: charset byte → 5-bit value.
	bech32CharsetRev [128]int8
)

func init() {
	for i := range bech32CharsetRev {
		bech32CharsetRev[i] = -1
	}
	for i, c := range bech32Charset {
		bech32CharsetRev[c] = int8(i)
	}
}

// DecodeOrchardRawFromUA decodes a ZIP-316 unified address and extracts
// the 43-byte raw Orchard receiver.
func DecodeOrchardRawFromUA(ua string) ([]byte, error) {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return nil, fmt.Errorf("empty address")
	}

	hrp, data5, err := bech32mDecode(ua)
	if err != nil {
		return nil, fmt.Errorf("bech32m decode: %w", err)
	}

	raw, err := convertBits(data5, 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("convert bits: %w", err)
	}

	if err := f4jumbleInvMut(raw); err != nil {
		return nil, fmt.Errorf("f4jumble inverse: %w", err)
	}

	// Verify HRP padding: the last zip316PaddingLen bytes must equal the HRP
	// padded with zeros.
	if len(raw) < zip316PaddingLen {
		return nil, fmt.Errorf("decoded data too short")
	}
	padding := raw[len(raw)-zip316PaddingLen:]
	expectedPadding := make([]byte, zip316PaddingLen)
	copy(expectedPadding, []byte(hrp))
	for i := range zip316PaddingLen {
		if padding[i] != expectedPadding[i] {
			return nil, fmt.Errorf("invalid HRP padding at byte %d", i)
		}
	}

	// Parse TLV entries from the data before the padding.
	tlv := raw[:len(raw)-zip316PaddingLen]
	offset := 0
	for offset < len(tlv) {
		typecode, n, err := readCompactSize(tlv, offset)
		if err != nil {
			return nil, fmt.Errorf("read typecode: %w", err)
		}
		offset += n

		length, n, err := readCompactSize(tlv, offset)
		if err != nil {
			return nil, fmt.Errorf("read length: %w", err)
		}
		offset += n

		if offset+int(length) > len(tlv) {
			return nil, fmt.Errorf("TLV entry overflows data")
		}

		if typecode == orchardTypeCode && length == orchardRawAddressLen {
			result := make([]byte, orchardRawAddressLen)
			copy(result, tlv[offset:offset+orchardRawAddressLen])
			return result, nil
		}
		offset += int(length)
	}

	return nil, fmt.Errorf("no Orchard receiver found in unified address")
}

// bech32mDecode decodes a bech32m string into HRP and 5-bit data (excluding checksum).
func bech32mDecode(addr string) (string, []byte, error) {
	if strings.ToLower(addr) != addr {
		return "", nil, fmt.Errorf("address must be lowercase")
	}
	sep := strings.LastIndexByte(addr, '1')
	if sep <= 0 || sep+7 > len(addr) {
		return "", nil, fmt.Errorf("invalid bech32m separator/length")
	}
	hrp := addr[:sep]
	if len(hrp) > zip316PaddingLen {
		return "", nil, fmt.Errorf("invalid hrp length")
	}
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", nil, fmt.Errorf("invalid hrp character")
		}
	}

	dataStr := addr[sep+1:]
	data5 := make([]byte, len(dataStr))
	for i := 0; i < len(dataStr); i++ {
		c := dataStr[i]
		if c >= 128 || bech32CharsetRev[c] < 0 {
			return "", nil, fmt.Errorf("invalid bech32m character: %c", c)
		}
		data5[i] = byte(bech32CharsetRev[c])
	}

	// Verify checksum (last 6 values).
	if len(data5) < 6 {
		return "", nil, fmt.Errorf("data too short for checksum")
	}
	values := make([]byte, 0, len(hrp)*2+1+len(data5))
	values = append(values, bech32HRPExpand(hrp)...)
	values = append(values, data5...)
	if bech32Polymod(values) != bech32mConst {
		return "", nil, fmt.Errorf("invalid bech32m checksum")
	}

	// Strip the 6-byte checksum from the returned data.
	return hrp, data5[:len(data5)-6], nil
}

// readCompactSize reads a Bitcoin-style CompactSize integer from data at offset.
func readCompactSize(data []byte, offset int) (uint64, int, error) {
	if offset >= len(data) {
		return 0, 0, fmt.Errorf("offset out of range")
	}
	first := data[offset]
	switch {
	case first <= 252:
		return uint64(first), 1, nil
	case first == 0xfd:
		if offset+3 > len(data) {
			return 0, 0, fmt.Errorf("truncated compact size (fd)")
		}
		v := uint64(data[offset+1]) | uint64(data[offset+2])<<8
		return v, 3, nil
	case first == 0xfe:
		if offset+5 > len(data) {
			return 0, 0, fmt.Errorf("truncated compact size (fe)")
		}
		v := uint64(data[offset+1]) | uint64(data[offset+2])<<8 |
			uint64(data[offset+3])<<16 | uint64(data[offset+4])<<24
		return v, 5, nil
	default: // 0xff
		if offset+9 > len(data) {
			return 0, 0, fmt.Errorf("truncated compact size (ff)")
		}
		v := uint64(data[offset+1]) | uint64(data[offset+2])<<8 |
			uint64(data[offset+3])<<16 | uint64(data[offset+4])<<24 |
			uint64(data[offset+5])<<32 | uint64(data[offset+6])<<40 |
			uint64(data[offset+7])<<48 | uint64(data[offset+8])<<56
		return v, 9, nil
	}
}

// f4jumbleInvMut applies the inverse F4Jumble transform in-place.
// Inverse order: H1 → G1 → H0 → G0 (reverse of G0 → H0 → G1 → H1).
func f4jumbleInvMut(message []byte) error {
	if len(message) < f4jumbleMinLen || len(message) > f4jumbleMaxLen {
		return fmt.Errorf("invalid f4jumble length: %d", len(message))
	}
	leftLen := len(message) / 2
	if leftLen > f4jumbleLeftMax {
		leftLen = f4jumbleLeftMax
	}
	left := message[:leftLen]
	right := message[leftLen:]

	// Inverse is applied in reverse order.
	if err := f4HRound(left, right, 1); err != nil {
		return err
	}
	if err := f4GRound(left, right, 1); err != nil {
		return err
	}
	if err := f4HRound(left, right, 0); err != nil {
		return err
	}
	if err := f4GRound(left, right, 0); err != nil {
		return err
	}
	return nil
}

// --- Shared primitives (same as withdrawcoordinator/zip316_orchard.go) ---

func convertBits(data []byte, fromBits uint, toBits uint, pad bool) ([]byte, error) {
	if fromBits == 0 || toBits == 0 || fromBits > 8 || toBits > 8 {
		return nil, fmt.Errorf("invalid bit groups")
	}
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

func appendCompactSize(dst []byte, v uint64) []byte {
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

func encodeOrchardRawUA(recipientRaw []byte, hrp string) (string, error) {
	if len(recipientRaw) != orchardRawAddressLen {
		return "", fmt.Errorf("orchard receiver must be %d bytes", orchardRawAddressLen)
	}
	if hrp == "" {
		return "", fmt.Errorf("empty hrp")
	}
	if len(hrp) > zip316PaddingLen {
		return "", fmt.Errorf("invalid hrp length")
	}
	if strings.ToLower(hrp) != hrp {
		return "", fmt.Errorf("hrp must be lowercase")
	}

	tlv := make([]byte, 0, 1+1+len(recipientRaw))
	tlv = appendCompactSize(tlv, orchardTypeCode)
	tlv = appendCompactSize(tlv, uint64(len(recipientRaw)))
	tlv = append(tlv, recipientRaw...)

	msg := make([]byte, len(tlv)+zip316PaddingLen)
	copy(msg, tlv)
	copy(msg[len(tlv):], []byte(hrp))

	if err := f4jumbleMut(msg); err != nil {
		return "", err
	}

	fiveBit, err := convertBits(msg, 8, 5, true)
	if err != nil {
		return "", err
	}

	checksum := bech32Checksum(hrp, fiveBit)
	data := append(fiveBit, checksum...)
	var out strings.Builder
	out.Grow(len(hrp) + 1 + len(data))
	out.WriteString(hrp)
	out.WriteByte('1')
	for _, v := range data {
		if int(v) >= len(bech32Charset) {
			return "", fmt.Errorf("invalid bech32 value")
		}
		out.WriteByte(bech32Charset[v])
	}
	return out.String(), nil
}

func bech32Checksum(hrp string, data []byte) []byte {
	values := make([]byte, 0, len(hrp)*2+1+len(data)+6)
	values = append(values, bech32HRPExpand(hrp)...)
	values = append(values, data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(values) ^ bech32mConst
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = byte((mod >> uint(5*(5-i))) & 31)
	}
	return out
}

func bech32HRPExpand(hrp string) []byte {
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

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if ((top >> uint(i)) & 1) != 0 {
				chk ^= bech32Generator[i]
			}
		}
	}
	return chk
}

func f4jumbleMut(message []byte) error {
	if len(message) < f4jumbleMinLen || len(message) > f4jumbleMaxLen {
		return fmt.Errorf("invalid f4jumble length")
	}
	leftLen := len(message) / 2
	if leftLen > f4jumbleLeftMax {
		leftLen = f4jumbleLeftMax
	}
	left := message[:leftLen]
	right := message[leftLen:]

	if err := f4GRound(left, right, 0); err != nil {
		return err
	}
	if err := f4HRound(left, right, 0); err != nil {
		return err
	}
	if err := f4GRound(left, right, 1); err != nil {
		return err
	}
	if err := f4HRound(left, right, 1); err != nil {
		return err
	}
	return nil
}

func f4HRound(left []byte, right []byte, round byte) error {
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

func f4GRound(left []byte, right []byte, round byte) error {
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
