package backoffice

import (
	"encoding/binary"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestExtractProtoString(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		fieldNum uint8
		want     string
		wantErr  bool
	}{
		{
			name:     "simple field 1",
			buf:      []byte{0x0a, 0x05, 'h', 'e', 'l', 'l', 'o'},
			fieldNum: 1,
			want:     "hello",
		},
		{
			name:     "field 1 after varint field 2",
			buf:      append([]byte{0x10, 0x2a}, []byte{0x0a, 0x03, 'f', 'o', 'o'}...), // field 2 varint 42, then field 1 string "foo"
			fieldNum: 1,
			want:     "foo",
		},
		{
			name:     "field not found",
			buf:      []byte{0x12, 0x03, 'a', 'b', 'c'}, // field 2 string "abc"
			fieldNum: 1,
			wantErr:  true,
		},
		{
			name:     "empty buffer",
			buf:      []byte{},
			fieldNum: 1,
			wantErr:  true,
		},
		{
			name:     "credits format",
			buf:      []byte{0x0a, 0x07, '1', '0', '0', '0', '0', '0', '0'},
			fieldNum: 1,
			want:     "1000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractProtoString(tt.buf, tt.fieldNum)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeVarint(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want uint64
		endI int
	}{
		{name: "single byte", buf: []byte{0x14}, want: 20, endI: 1},
		{name: "zero", buf: []byte{0x00}, want: 0, endI: 1},
		{name: "127", buf: []byte{0x7f}, want: 127, endI: 1},
		{name: "128 (two bytes)", buf: []byte{0x80, 0x01}, want: 128, endI: 2},
		{name: "300 (two bytes)", buf: []byte{0xac, 0x02}, want: 300, endI: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, endI := decodeVarint(tt.buf, 0)
			if val != tt.want {
				t.Errorf("value: got %d, want %d", val, tt.want)
			}
			if endI != tt.endI {
				t.Errorf("endI: got %d, want %d", endI, tt.endI)
			}
		})
	}
}

func TestFetchSP1Balance_ProtobufEncoding(t *testing.T) {
	// Verify that the protobuf encoding for GetBalanceRequest is correct.
	// GetBalanceRequest{bytes address = 1} for a known address.
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	addrBytes := addr.Bytes()

	// Build proto the same way fetchSP1Balance does.
	proto := make([]byte, 0, 2+len(addrBytes))
	proto = append(proto, 0x0a, byte(len(addrBytes)))
	proto = append(proto, addrBytes...)

	// Verify structure: tag 0x0a (field 1, wire type 2), length 20, then 20 address bytes.
	if len(proto) != 22 {
		t.Fatalf("proto length: got %d, want 22", len(proto))
	}
	if proto[0] != 0x0a {
		t.Errorf("tag byte: got 0x%02x, want 0x0a", proto[0])
	}
	if proto[1] != 20 {
		t.Errorf("length byte: got %d, want 20", proto[1])
	}

	// Build gRPC frame.
	frame := make([]byte, 5+len(proto))
	frame[0] = 0 // no compression
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(proto)))
	copy(frame[5:], proto)

	if len(frame) != 27 {
		t.Fatalf("frame length: got %d, want 27", len(frame))
	}
	if frame[0] != 0 {
		t.Error("compression flag should be 0")
	}
	msgLen := binary.BigEndian.Uint32(frame[1:5])
	if msgLen != 22 {
		t.Errorf("frame message length: got %d, want 22", msgLen)
	}

	// Verify we can decode the response format.
	// Simulate GetBalanceResponse{string amount = 1} = "500000"
	respProto := []byte{0x0a, 0x06, '5', '0', '0', '0', '0', '0'}
	credits, err := extractProtoString(respProto, 1)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if credits != "500000" {
		t.Errorf("credits: got %q, want %q", credits, "500000")
	}
}
