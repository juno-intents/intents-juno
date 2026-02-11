package proverexec

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

var ErrInvalidConfig = errors.New("proverexec: invalid config")

type execCommandFn func(ctx context.Context, bin string, stdin []byte) ([]byte, []byte, error)

type Client struct {
	bin string

	maxResponseBytes int
	execCommand      execCommandFn
}

func New(bin string, maxResponseBytes int) (*Client, error) {
	if strings.TrimSpace(bin) == "" {
		return nil, fmt.Errorf("%w: missing prover binary", ErrInvalidConfig)
	}
	if maxResponseBytes <= 0 {
		return nil, fmt.Errorf("%w: max response bytes must be > 0", ErrInvalidConfig)
	}
	return &Client{
		bin:              bin,
		maxResponseBytes: maxResponseBytes,
		execCommand:      runExecCommand,
	}, nil
}

func (c *Client) Prove(ctx context.Context, imageID common.Hash, journal []byte) ([]byte, error) {
	if c == nil || c.execCommand == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidConfig)
	}
	if len(journal) == 0 {
		return nil, fmt.Errorf("%w: empty journal", ErrInvalidConfig)
	}

	reqBody, err := json.Marshal(map[string]any{
		"version": "prover.request.v1",
		"imageId": imageID.Hex(),
		"journal": "0x" + hex.EncodeToString(journal),
	})
	if err != nil {
		return nil, fmt.Errorf("proverexec: marshal request: %w", err)
	}

	stdout, stderr, err := c.execCommand(ctx, c.bin, reqBody)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(stdout))
		}
		if msg == "" {
			return nil, fmt.Errorf("proverexec: execute prover: %w", err)
		}
		return nil, fmt.Errorf("proverexec: execute prover: %w: %s", err, msg)
	}
	if len(stdout) > c.maxResponseBytes {
		return nil, fmt.Errorf("proverexec: response too large")
	}

	var resp struct {
		Version string `json:"version"`
		Seal    string `json:"seal"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(stdout, &resp); err != nil {
		return nil, fmt.Errorf("proverexec: decode response: %w", err)
	}
	if resp.Version != "prover.response.v1" {
		return nil, fmt.Errorf("proverexec: unexpected response version %q", resp.Version)
	}
	if strings.TrimSpace(resp.Error) != "" {
		return nil, fmt.Errorf("proverexec: %s", strings.TrimSpace(resp.Error))
	}
	if strings.TrimSpace(resp.Seal) == "" {
		return nil, fmt.Errorf("proverexec: empty seal")
	}
	b, err := decodeHexBytes(resp.Seal)
	if err != nil {
		return nil, fmt.Errorf("proverexec: decode seal: %w", err)
	}
	return b, nil
}

func runExecCommand(ctx context.Context, bin string, stdin []byte) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, bin)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func decodeHexBytes(s string) ([]byte, error) {
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
