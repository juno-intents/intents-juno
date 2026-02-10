package tss

import (
	"encoding/hex"
	"testing"
)

func seq32(start byte) (out [32]byte) {
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
}

func TestFormatAndParseSessionID_RoundTrip(t *testing.T) {
	t.Parallel()

	want := seq32(0x10)
	s := FormatSessionID(want)

	got, err := ParseSessionID(s)
	if err != nil {
		t.Fatalf("ParseSessionID: %v", err)
	}
	if got != want {
		t.Fatalf("mismatch: got %x want %x", got, want)
	}
}

func TestParseSessionID_AcceptsNo0xPrefix(t *testing.T) {
	t.Parallel()

	want := seq32(0x20)
	s := hex.EncodeToString(want[:])

	got, err := ParseSessionID(s)
	if err != nil {
		t.Fatalf("ParseSessionID: %v", err)
	}
	if got != want {
		t.Fatalf("mismatch")
	}
}

func TestParseSessionID_RejectsWrongLength(t *testing.T) {
	t.Parallel()

	if _, err := ParseSessionID("0x1234"); err == nil {
		t.Fatalf("expected error")
	}
}

