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
	execExtendSignJSONVersion = "v1"
)

type execExtendSignerCommandFn func(ctx context.Context, bin string, args []string) ([]byte, []byte, error)

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

	stdout, stderr, err := s.execCommand(ctx, s.bin, []string{
		"sign-digest",
		"--digest", digest.Hex(),
		"--json",
	})
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

	var env struct {
		Version string          `json:"version"`
		Status  string          `json:"status"`
		Data    json.RawMessage `json:"data"`
		Error   *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(stdout, &env); err != nil {
		return nil, fmt.Errorf("withdrawcoordinator: decode extend signer response: %w", err)
	}
	if env.Version != execExtendSignJSONVersion {
		return nil, fmt.Errorf("withdrawcoordinator: unexpected extend signer response version %q", env.Version)
	}
	if env.Status == "err" {
		msg := "unknown extend signer error"
		if env.Error != nil && strings.TrimSpace(env.Error.Message) != "" {
			msg = strings.TrimSpace(env.Error.Message)
		}
		if env.Error != nil && strings.TrimSpace(env.Error.Code) != "" {
			return nil, fmt.Errorf("withdrawcoordinator: extend signer (%s): %s", strings.TrimSpace(env.Error.Code), msg)
		}
		return nil, fmt.Errorf("withdrawcoordinator: extend signer: %s", msg)
	}
	if env.Status != "ok" {
		return nil, fmt.Errorf("withdrawcoordinator: invalid extend signer status %q", env.Status)
	}

	var data struct {
		Signatures []string `json:"signatures"`
		Signature  string   `json:"signature"`
	}
	if len(env.Data) == 0 {
		return nil, fmt.Errorf("withdrawcoordinator: extend signer returned empty data")
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return nil, fmt.Errorf("withdrawcoordinator: decode extend signer data: %w", err)
	}

	hexSigs := data.Signatures
	if len(hexSigs) == 0 && strings.TrimSpace(data.Signature) != "" {
		hexSigs = []string{data.Signature}
	}
	if len(hexSigs) == 0 {
		return nil, fmt.Errorf("withdrawcoordinator: extend signer returned no signatures")
	}

	sigs := make([][]byte, 0, len(hexSigs))
	for i, sHex := range hexSigs {
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

func runExecExtendSignerCommand(ctx context.Context, bin string, args []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
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
