package queueauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	EnvelopeVersion = "queue.auth.v1"
	DefaultKeyID    = "default"

	DefaultKeyIDEnv = "JUNO_QUEUE_CRITICAL_KEY_ID"
	DefaultHMACEnv  = "JUNO_QUEUE_CRITICAL_HMAC_KEY"
)

var (
	ErrCriticalTopicAuthRequired = errors.New("queueauth: critical topic signing key required")
	ErrInvalidEnvelope           = errors.New("queueauth: invalid signed envelope")
	ErrEnvelopeTopicMismatch     = errors.New("queueauth: envelope topic mismatch")
	ErrUnexpectedKeyID           = errors.New("queueauth: unexpected key id")
	ErrInvalidMAC                = errors.New("queueauth: invalid envelope mac")
)

type Envelope struct {
	Version   string    `json:"version"`
	Topic     string    `json:"topic"`
	Timestamp time.Time `json:"timestamp"`
	Nonce     string    `json:"nonce"`
	Payload   []byte    `json:"payload"`
	KeyID     string    `json:"keyId"`
	MAC       string    `json:"mac"`
}

type Config struct {
	KeyID  string
	Secret []byte
	Now    func() time.Time
	Rand   io.Reader
}

type Codec struct {
	keyID  string
	secret []byte
	now    func() time.Time
	rand   io.Reader
}

var criticalTopics = map[string]struct{}{
	"deposits.event.v2":         {},
	"withdrawals.requested.v2":  {},
	"checkpoints.signatures.v1": {},
	"checkpoints.package.v1":    {},
	"checkpoints.packages.v1":   {},
}

func IsCriticalTopic(topic string) bool {
	_, ok := criticalTopics[strings.TrimSpace(topic)]
	return ok
}

func ResolveKeyID(explicit, envName string) string {
	if v := strings.TrimSpace(explicit); v != "" {
		return v
	}
	if envName != "" {
		if v := strings.TrimSpace(os.Getenv(envName)); v != "" {
			return v
		}
	}
	return DefaultKeyID
}

func ResolveSecret(explicit, envName string) []byte {
	if explicit != "" {
		return []byte(explicit)
	}
	if envName != "" {
		if v := os.Getenv(envName); v != "" {
			return []byte(v)
		}
	}
	return nil
}

func New(cfg Config) *Codec {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	random := cfg.Rand
	if random == nil {
		random = rand.Reader
	}
	keyID := strings.TrimSpace(cfg.KeyID)
	if keyID == "" {
		keyID = DefaultKeyID
	}
	return &Codec{
		keyID:  keyID,
		secret: append([]byte(nil), cfg.Secret...),
		now:    now,
		rand:   random,
	}
}

func NewDefaultCodec() *Codec {
	return New(Config{
		KeyID:  ResolveKeyID("", DefaultKeyIDEnv),
		Secret: ResolveSecret("", DefaultHMACEnv),
	})
}

func WrapPayload(codec *Codec, topic string, payload []byte) ([]byte, error) {
	if codec == nil {
		return append([]byte(nil), payload...), nil
	}
	return codec.Wrap(topic, payload)
}

func UnwrapPayload(codec *Codec, topic string, payload []byte) ([]byte, error) {
	if codec == nil {
		return append([]byte(nil), payload...), nil
	}
	return codec.Unwrap(topic, payload)
}

func (c *Codec) Wrap(topic string, payload []byte) ([]byte, error) {
	topic = strings.TrimSpace(topic)
	if !IsCriticalTopic(topic) {
		return append([]byte(nil), payload...), nil
	}
	if c == nil || len(c.secret) == 0 {
		return nil, ErrCriticalTopicAuthRequired
	}
	nonce, err := randomNonce(c.rand, 16)
	if err != nil {
		return nil, fmt.Errorf("queueauth: random nonce: %w", err)
	}
	env := Envelope{
		Version:   EnvelopeVersion,
		Topic:     topic,
		Timestamp: c.now().UTC(),
		Nonce:     nonce,
		Payload:   append([]byte(nil), payload...),
		KeyID:     c.keyID,
	}
	env.MAC = hex.EncodeToString(signEnvelope(c.secret, env))
	encoded, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("queueauth: marshal envelope: %w", err)
	}
	return encoded, nil
}

func (c *Codec) Unwrap(topic string, payload []byte) ([]byte, error) {
	topic = strings.TrimSpace(topic)
	if !IsCriticalTopic(topic) {
		return append([]byte(nil), payload...), nil
	}
	if c == nil || len(c.secret) == 0 {
		return nil, ErrCriticalTopicAuthRequired
	}

	var env Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("%w: decode envelope: %v", ErrInvalidEnvelope, err)
	}
	if env.Version != EnvelopeVersion {
		return nil, fmt.Errorf("%w: unexpected version %q", ErrInvalidEnvelope, env.Version)
	}
	if strings.TrimSpace(env.Topic) != topic {
		return nil, fmt.Errorf("%w: got %q want %q", ErrEnvelopeTopicMismatch, env.Topic, topic)
	}
	if strings.TrimSpace(env.KeyID) != c.keyID {
		return nil, fmt.Errorf("%w: got %q want %q", ErrUnexpectedKeyID, env.KeyID, c.keyID)
	}
	mac, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(env.MAC), "0x"))
	if err != nil {
		return nil, fmt.Errorf("%w: decode mac: %v", ErrInvalidEnvelope, err)
	}
	expected := signEnvelope(c.secret, Envelope{
		Version:   env.Version,
		Topic:     env.Topic,
		Timestamp: env.Timestamp.UTC(),
		Nonce:     env.Nonce,
		Payload:   env.Payload,
		KeyID:     env.KeyID,
	})
	if !hmac.Equal(mac, expected) {
		return nil, ErrInvalidMAC
	}
	return append([]byte(nil), env.Payload...), nil
}

func randomNonce(r io.Reader, n int) (string, error) {
	if n <= 0 {
		return "", nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func signEnvelope(secret []byte, env Envelope) []byte {
	mac := hmac.New(sha256.New, secret)
	writeMACPart(mac, env.Version)
	writeMACPart(mac, env.Topic)
	writeMACPart(mac, env.Timestamp.UTC().Format(time.RFC3339Nano))
	writeMACPart(mac, env.Nonce)
	writeMACPart(mac, env.KeyID)
	writeMACBytes(mac, env.Payload)
	return mac.Sum(nil)
}

func writeMACPart(w io.Writer, part string) {
	writeMACBytes(w, []byte(part))
}

func writeMACBytes(w io.Writer, part []byte) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(part)))
	_, _ = w.Write(lenBuf[:])
	_, _ = w.Write(part)
}
