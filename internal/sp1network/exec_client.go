package sp1network

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os/exec"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

const (
	versionSP1BalanceRequest  = "sp1.balance.request.v1"
	versionSP1BalanceResponse = "sp1.balance.response.v1"
)

type execCommandFn func(ctx context.Context, bin string, stdin []byte) ([]byte, []byte, error)

type ExecClientConfig struct {
	Binary           string
	MaxResponseBytes int
}

type ExecClient struct {
	bin              string
	maxResponseBytes int
	execCommand      execCommandFn
}

func NewExecClient(cfg ExecClientConfig) (*ExecClient, error) {
	if strings.TrimSpace(cfg.Binary) == "" {
		return nil, fmt.Errorf("%w: missing sp1 binary", ErrInvalidConfig)
	}
	if cfg.MaxResponseBytes <= 0 {
		return nil, fmt.Errorf("%w: max response bytes must be > 0", ErrInvalidConfig)
	}
	return &ExecClient{
		bin:              cfg.Binary,
		maxResponseBytes: cfg.MaxResponseBytes,
		execCommand:      runExecCommand,
	}, nil
}

func (c *ExecClient) RequestorBalanceWei(ctx context.Context, requestor common.Address) (*big.Int, error) {
	if requestor == (common.Address{}) {
		return nil, fmt.Errorf("%w: requestor address is required", ErrInvalidConfig)
	}
	body, err := json.Marshal(map[string]any{
		"version":           versionSP1BalanceRequest,
		"requestor_address": requestor.Hex(),
	})
	if err != nil {
		return nil, fmt.Errorf("sp1network: marshal balance request: %w", err)
	}
	stdout, stderr, err := c.run(ctx, body)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(stdout))
		}
		return nil, fmt.Errorf("sp1network: execute balance request: %w: %s", err, msg)
	}
	var resp struct {
		Version    string `json:"version"`
		BalanceWei string `json:"balance_wei"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(stdout, &resp); err != nil {
		return nil, fmt.Errorf("sp1network: decode balance response: %w", err)
	}
	if resp.Version != versionSP1BalanceResponse {
		return nil, fmt.Errorf("sp1network: unexpected balance response version %q", resp.Version)
	}
	if strings.TrimSpace(resp.Error) != "" {
		return nil, fmt.Errorf("sp1network: %s", strings.TrimSpace(resp.Error))
	}
	balance, ok := new(big.Int).SetString(strings.TrimSpace(resp.BalanceWei), 10)
	if !ok {
		return nil, fmt.Errorf("sp1network: invalid balance_wei")
	}
	return balance, nil
}

func (c *ExecClient) run(ctx context.Context, stdin []byte) ([]byte, []byte, error) {
	if c == nil || c.execCommand == nil {
		return nil, nil, fmt.Errorf("%w: nil exec client", ErrInvalidConfig)
	}
	stdout, stderr, err := c.execCommand(ctx, c.bin, stdin)
	if len(stdout) > c.maxResponseBytes {
		return nil, nil, fmt.Errorf("sp1network: response too large")
	}
	return stdout, stderr, err
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
