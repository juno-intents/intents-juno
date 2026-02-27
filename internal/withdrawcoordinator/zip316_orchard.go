package withdrawcoordinator

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
)

func bech32HRPFromAddress(address string) (string, error) {
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
	if len(hrp) > zip316PaddingLen {
		return "", fmt.Errorf("invalid hrp length")
	}
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", fmt.Errorf("invalid hrp")
		}
	}
	return hrp, nil
}

func encodeOrchardRawUnifiedAddress(recipientRaw []byte, hrp string) (string, error) {
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
