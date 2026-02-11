package withdrawcoordinator

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

const (
	execExtendSignRequestVersion  = "withdraw.extend_sign.request.v1"
	execExtendSignResponseVersion = "withdraw.extend_sign.response.v1"
)

type execExtendSignerCommandFn func(ctx context.Context, bin string, stdin []byte) ([]byte, []byte, error)

type ExecExtendSigner struct {
	bin string

	maxResponseBytes int
	execCommand      execExtendSignerCommandFn
}

func NewExecExtendSigner(bin string, maxResponseBytes int) (*ExecExtendSigner, error) {
	if strings.TrimSpace(bin) == "" {
		return nil, fmt.Errorf("%w: missing extend signer binary", ErrInvalidExpiryExtenderConfig)
	}
	if maxResponseBytes <= 0 {
		return nil, fmt.Errorf("%w: max response bytes must be > 0", ErrInvalidExpiryExtenderConfig)
	}

	return &ExecExtendSigner{
		bin:              bin,
		maxResponseBytes: maxResponseBytes,
		execCommand:      runExecExtendSignerCommand,
	}, nil
}

func (s *ExecExtendSigner) SignExtendDigest(ctx context.Context, digest common.Hash) ([][]byte, error) {
	if s == nil || s.execCommand == nil {
		return nil, fmt.Errorf("%w: nil extend signer", ErrInvalidExpiryExtenderConfig)
	}

	reqBody, err := json.Marshal(map[string]any{
		"version": execExtendSignRequestVersion,
		"digest":  digest.Hex(),
	})
	if err != nil {
		return nil, fmt.Errorf("withdrawcoordinator: marshal extend signer request: %w", err)
	}

	stdout, stderr, err := s.execCommand(ctx, s.bin, reqBody)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(stdout))
		}
		if msg == "" {
			return nil, fmt.Errorf("withdrawcoordinator: execute extend signer: %w", err)
		}
		return nil, fmt.Errorf("withdrawcoordinator: execute extend signer: %w: %s", err, msg)
	}
	if len(stdout) > s.maxResponseBytes {
		return nil, fmt.Errorf("withdrawcoordinator: extend signer response too large")
	}

	var resp struct {
		Version    string   `json:"version"`
		Signatures []string `json:"signatures"`
		Error      string   `json:"error"`
	}
	if err := json.Unmarshal(stdout, &resp); err != nil {
		return nil, fmt.Errorf("withdrawcoordinator: decode extend signer response: %w", err)
	}
	if resp.Version != execExtendSignResponseVersion {
		return nil, fmt.Errorf("withdrawcoordinator: unexpected extend signer response version %q", resp.Version)
	}
	if strings.TrimSpace(resp.Error) != "" {
		return nil, fmt.Errorf("withdrawcoordinator: extend signer: %s", strings.TrimSpace(resp.Error))
	}
	if len(resp.Signatures) == 0 {
		return nil, fmt.Errorf("withdrawcoordinator: extend signer returned no signatures")
	}

	sigs := make([][]byte, 0, len(resp.Signatures))
	for i, sHex := range resp.Signatures {
		sig, err := decodeHexBytesStrict(sHex)
		if err != nil {
			return nil, fmt.Errorf("withdrawcoordinator: decode signature[%d]: %w", i, err)
		}
		if len(sig) != 65 {
			return nil, fmt.Errorf("withdrawcoordinator: signature[%d] invalid length %d", i, len(sig))
		}
		if sig[64] != 27 && sig[64] != 28 {
			return nil, fmt.Errorf("withdrawcoordinator: signature[%d] invalid v %d", i, sig[64])
		}
		sigs = append(sigs, sig)
	}

	return sigs, nil
}

func runExecExtendSignerCommand(ctx context.Context, bin string, stdin []byte) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, bin)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func decodeHexBytesStrict(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if s == "" {
		return nil, fmt.Errorf("empty hex")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}
