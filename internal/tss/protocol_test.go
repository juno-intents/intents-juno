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

func TestFormatAndParseBatchID_RoundTrip(t *testing.T) {
	t.Parallel()

	want := seq32(0x30)
	s := FormatBatchID(want)

	got, err := ParseBatchID(s)
	if err != nil {
		t.Fatalf("ParseBatchID: %v", err)
	}
	if got != want {
		t.Fatalf("mismatch: got %x want %x", got, want)
	}
}

func TestDeriveSigningSessionID_DiffersAcrossPlans(t *testing.T) {
	t.Parallel()

	batchID := seq32(0x40)
	id0 := DeriveSigningSessionID(batchID, []byte(`{"v":1}`))
	id1 := DeriveSigningSessionID(batchID, []byte(`{"v":2}`))
	if id0 == id1 {
		t.Fatalf("expected different signing session ids for different plans")
	}
}
