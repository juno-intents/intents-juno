package boundless

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/proverexec"
)

var ErrInvalidConfig = errors.New("boundless: invalid config")

type Backend string

const (
	// BackendBoundless routes proofs through the Boundless-facing prover adapter.
	BackendBoundless Backend = "boundless"
	// BackendSelf routes proofs through a self-hosted prover adapter.
	BackendSelf Backend = "self"
)

func (b Backend) String() string {
	return string(b)
}

type Client interface {
	Prove(ctx context.Context, imageID common.Hash, journal []byte, privateInput []byte) ([]byte, error)
}

type Config struct {
	// Backend selects the prover backend. Empty defaults to boundless.
	Backend string

	// ProverBin is the command binary implementing prover.request.v1/prover.response.v1.
	ProverBin string

	// MaxResponseBytes caps stdout payload bytes read from the prover binary.
	MaxResponseBytes int
}

func ParseBackend(v string) (Backend, error) {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case BackendBoundless.String():
		return BackendBoundless, nil
	case BackendSelf.String():
		return BackendSelf, nil
	default:
		return "", fmt.Errorf("%w: unsupported prover backend %q (supported: %q, %q)", ErrInvalidConfig, v, BackendBoundless, BackendSelf)
	}
}

func New(cfg Config) (Client, error) {
	backend := BackendBoundless
	if strings.TrimSpace(cfg.Backend) != "" {
		parsed, err := ParseBackend(cfg.Backend)
		if err != nil {
			return nil, err
		}
		backend = parsed
	}

	switch backend {
	case BackendBoundless:
		return newBoundlessClient(cfg)
	case BackendSelf:
		return newSelfClient(cfg)
	default:
		return nil, fmt.Errorf("%w: unsupported prover backend %q", ErrInvalidConfig, backend)
	}
}

func newBoundlessClient(cfg Config) (Client, error) {
	client, err := proverexec.New(cfg.ProverBin, cfg.MaxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: boundless backend: %w", ErrInvalidConfig, err)
	}
	return client, nil
}

func newSelfClient(cfg Config) (Client, error) {
	client, err := proverexec.New(cfg.ProverBin, cfg.MaxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: self backend: %w", ErrInvalidConfig, err)
	}
	return client, nil
}
