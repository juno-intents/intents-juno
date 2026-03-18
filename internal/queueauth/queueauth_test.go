package queueauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestCodec_RoundTripCriticalTopic(t *testing.T) {
	t.Parallel()

	codec := New(Config{
		KeyID:  "ops-1",
		Secret: []byte("super-secret-key"),
		Now: func() time.Time {
			return time.Unix(1_700_000_000, 0).UTC()
		},
		Rand: bytes.NewReader(bytes.Repeat([]byte{0x2a}, 16)),
	})

	wire, err := codec.Wrap("withdrawals.requested.v2", []byte(`{"version":"withdrawals.requested.v2"}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if bytes.Contains(wire, []byte(`"version":"withdrawals.requested.v2"`)) {
		t.Fatalf("expected wrapped envelope, got raw payload %s", wire)
	}

	raw, err := codec.Unwrap("withdrawals.requested.v2", wire)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if got, want := string(raw), `{"version":"withdrawals.requested.v2"}`; got != want {
		t.Fatalf("payload mismatch: got %q want %q", got, want)
	}
}

func TestCodec_PassThroughNonCriticalTopic(t *testing.T) {
	t.Parallel()

	codec := New(Config{})
	raw, err := codec.Wrap("proof.requests.v1", []byte("hello"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if got := string(raw); got != "hello" {
		t.Fatalf("got %q want hello", got)
	}

	unwrapped, err := codec.Unwrap("proof.requests.v1", raw)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if got := string(unwrapped); got != "hello" {
		t.Fatalf("got %q want hello", got)
	}
}

func TestCodec_RejectsUnsignedCriticalPayload(t *testing.T) {
	t.Parallel()

	codec := New(Config{KeyID: "ops-1", Secret: []byte("super-secret-key")})
	_, err := codec.Unwrap("deposits.event.v2", []byte(`{"version":"deposits.event.v2"}`))
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("err = %v, want %v", err, ErrInvalidEnvelope)
	}
}

func TestCodec_RejectsTamperedPayload(t *testing.T) {
	t.Parallel()

	codec := New(Config{
		KeyID:  "ops-1",
		Secret: []byte("super-secret-key"),
		Now: func() time.Time {
			return time.Unix(1_700_000_000, 0).UTC()
		},
		Rand: bytes.NewReader(bytes.Repeat([]byte{0x2a}, 16)),
	})

	wire, err := codec.Wrap("checkpoints.signatures.v1", []byte(`{"version":"checkpoints.signature.v1"}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(wire, &env); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	env.MAC = "00" + env.MAC[2:]
	wire, err = json.Marshal(env)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	_, err = codec.Unwrap("checkpoints.signatures.v1", wire)
	if !errors.Is(err, ErrInvalidMAC) {
		t.Fatalf("err = %v, want %v", err, ErrInvalidMAC)
	}
}

func TestCodec_RejectsUnexpectedKeyID(t *testing.T) {
	t.Parallel()

	writer := New(Config{
		KeyID:  "ops-1",
		Secret: []byte("super-secret-key"),
		Now: func() time.Time {
			return time.Unix(1_700_000_000, 0).UTC()
		},
		Rand: bytes.NewReader(bytes.Repeat([]byte{0x2a}, 16)),
	})
	reader := New(Config{
		KeyID:  "ops-2",
		Secret: []byte("super-secret-key"),
	})

	wire, err := writer.Wrap("checkpoints.packages.v1", []byte(`{"version":"checkpoints.package.v1"}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	_, err = reader.Unwrap("checkpoints.packages.v1", wire)
	if !errors.Is(err, ErrUnexpectedKeyID) {
		t.Fatalf("err = %v, want %v", err, ErrUnexpectedKeyID)
	}
}
