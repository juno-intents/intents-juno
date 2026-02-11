package boundless

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os/exec"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type execCommandFn func(ctx context.Context, bin string, stdin []byte) ([]byte, []byte, error)

type ExecClientConfig struct {
	Binary           string
	MaxResponseBytes int
	OwnerAddress     common.Address
	OwnerPrivateKey  string
}

type ExecClient struct {
	bin              string
	maxResponseBytes int
	ownerAddress     common.Address
	ownerPrivateKey  string
	execCommand      execCommandFn
}

func NewExecClient(cfg ExecClientConfig) (*ExecClient, error) {
	if strings.TrimSpace(cfg.Binary) == "" {
		return nil, fmt.Errorf("%w: missing boundless binary", ErrInvalidConfig)
	}
	if cfg.MaxResponseBytes <= 0 {
		return nil, fmt.Errorf("%w: max response bytes must be > 0", ErrInvalidConfig)
	}
	return &ExecClient{
		bin:              cfg.Binary,
		maxResponseBytes: cfg.MaxResponseBytes,
		ownerAddress:     cfg.OwnerAddress,
		ownerPrivateKey:  cfg.OwnerPrivateKey,
		execCommand:      runExecCommand,
	}, nil
}

func (c *ExecClient) SubmitOffchain(ctx context.Context, req SubmitRequest) (SubmitResponse, error) {
	body, err := json.Marshal(map[string]any{
		"version":               "boundless.submit.offchain.v1",
		"request_id":            req.RequestID,
		"chain_id":              req.ChainID,
		"requestor_address":     req.RequestorAddress.Hex(),
		"requestor_private_key": req.RequestorPrivateKey,
		"order_stream_url":      req.OrderStreamURL,
		"market_address":        req.MarketAddress.Hex(),
		"job_id":                req.JobID.Hex(),
		"pipeline":              req.Pipeline,
		"image_id":              req.ImageID.Hex(),
		"journal":               "0x" + hex.EncodeToString(req.Journal),
		"private_input":         "0x" + hex.EncodeToString(req.PrivateInput),
		"deadline":              req.Deadline.UTC().Format(time.RFC3339),
		"priority":              req.Priority,
	})
	if err != nil {
		return SubmitResponse{}, fmt.Errorf("boundless: marshal offchain request: %w", err)
	}
	return c.submit(ctx, body, "offchain")
}

func (c *ExecClient) SubmitOnchain(ctx context.Context, req OnchainSubmitRequest) (SubmitResponse, error) {
	body, err := json.Marshal(map[string]any{
		"version":                 "boundless.submit.onchain.v1",
		"request_id":              req.RequestID,
		"chain_id":                req.ChainID,
		"requestor_address":       req.RequestorAddress.Hex(),
		"requestor_private_key":   req.RequestorPrivateKey,
		"market_address":          req.MarketAddress.Hex(),
		"job_id":                  req.JobID.Hex(),
		"pipeline":                req.Pipeline,
		"image_id":                req.ImageID.Hex(),
		"journal":                 "0x" + hex.EncodeToString(req.Journal),
		"private_input":           "0x" + hex.EncodeToString(req.PrivateInput),
		"deadline":                req.Deadline.UTC().Format(time.RFC3339),
		"priority":                req.Priority,
		"funding_mode":            req.FundingMode,
		"min_balance_wei":         decimalString(req.MinBalanceWei),
		"target_balance_wei":      decimalString(req.TargetBalanceWei),
		"max_price_per_proof_wei": decimalString(req.MaxPricePerProofWei),
		"max_stake_per_proof_wei": decimalString(req.MaxStakePerProofWei),
	})
	if err != nil {
		return SubmitResponse{}, fmt.Errorf("boundless: marshal onchain request: %w", err)
	}
	return c.submit(ctx, body, "onchain")
}

func (c *ExecClient) submit(ctx context.Context, body []byte, defaultPath string) (SubmitResponse, error) {
	stdout, stderr, err := c.run(ctx, body)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(stdout))
		}
		return SubmitResponse{}, &SubmitError{
			Code:      "boundless_exec_error",
			Retryable: true,
			Cause:     fmt.Errorf("%v: %s", err, msg),
		}
	}

	var resp struct {
		Version        string            `json:"version"`
		RequestID      uint64            `json:"request_id"`
		SubmissionPath string            `json:"submission_path"`
		Seal           string            `json:"seal"`
		Metadata       map[string]string `json:"metadata"`
		TxHash         string            `json:"tx_hash"`
		Error          string            `json:"error"`
		ErrorCode      string            `json:"error_code"`
		Retryable      bool              `json:"retryable"`
	}
	if err := json.Unmarshal(stdout, &resp); err != nil {
		return SubmitResponse{}, &SubmitError{
			Code:      "boundless_decode_error",
			Retryable: true,
			Cause:     err,
		}
	}
	if strings.TrimSpace(resp.Error) != "" {
		code := strings.TrimSpace(resp.ErrorCode)
		if code == "" {
			code = "boundless_submit_error"
		}
		return SubmitResponse{}, &SubmitError{
			Code:      code,
			Retryable: resp.Retryable,
			Cause:     fmt.Errorf("%s", strings.TrimSpace(resp.Error)),
		}
	}

	seal, err := decodeHexMaybe(resp.Seal)
	if err != nil {
		return SubmitResponse{}, &SubmitError{
			Code:      "boundless_invalid_seal",
			Retryable: false,
			Cause:     err,
		}
	}
	path := strings.TrimSpace(resp.SubmissionPath)
	if path == "" {
		path = defaultPath
	}
	return SubmitResponse{
		RequestID:      resp.RequestID,
		SubmissionPath: path,
		Seal:           seal,
		Metadata:       CopyMetadata(resp.Metadata),
		TxHash:         strings.TrimSpace(resp.TxHash),
	}, nil
}

func (c *ExecClient) RequestorBalanceWei(ctx context.Context, requestor common.Address) (*big.Int, error) {
	body, err := json.Marshal(map[string]any{
		"version":           "boundless.balance.request.v1",
		"requestor_address": requestor.Hex(),
	})
	if err != nil {
		return nil, err
	}
	stdout, _, err := c.run(ctx, body)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Version    string `json:"version"`
		BalanceWei string `json:"balance_wei"`
	}
	if err := json.Unmarshal(stdout, &resp); err != nil {
		return nil, fmt.Errorf("boundless: decode balance response: %w", err)
	}
	bal, ok := new(big.Int).SetString(strings.TrimSpace(resp.BalanceWei), 10)
	if !ok {
		return nil, fmt.Errorf("boundless: invalid balance_wei")
	}
	return bal, nil
}

func (c *ExecClient) TopUpRequestor(ctx context.Context, requestor common.Address, amountWei *big.Int) (string, error) {
	body, err := json.Marshal(map[string]any{
		"version":           "boundless.topup.request.v1",
		"owner_address":     c.ownerAddress.Hex(),
		"owner_private_key": c.ownerPrivateKey,
		"requestor_address": requestor.Hex(),
		"amount_wei":        decimalString(amountWei),
	})
	if err != nil {
		return "", err
	}
	stdout, _, err := c.run(ctx, body)
	if err != nil {
		return "", err
	}
	var resp struct {
		Version   string `json:"version"`
		TxHash    string `json:"tx_hash"`
		Error     string `json:"error"`
		ErrorCode string `json:"error_code"`
	}
	if err := json.Unmarshal(stdout, &resp); err != nil {
		return "", fmt.Errorf("boundless: decode topup response: %w", err)
	}
	if strings.TrimSpace(resp.Error) != "" {
		return "", &SubmitError{
			Code:      strings.TrimSpace(resp.ErrorCode),
			Retryable: true,
			Cause:     fmt.Errorf("%s", strings.TrimSpace(resp.Error)),
		}
	}
	return strings.TrimSpace(resp.TxHash), nil
}

func (c *ExecClient) run(ctx context.Context, stdin []byte) ([]byte, []byte, error) {
	if c == nil || c.execCommand == nil {
		return nil, nil, fmt.Errorf("%w: nil exec client", ErrInvalidConfig)
	}
	stdout, stderr, err := c.execCommand(ctx, c.bin, stdin)
	if len(stdout) > c.maxResponseBytes {
		return nil, nil, fmt.Errorf("boundless: response too large")
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

func decimalString(v *big.Int) string {
	if v == nil {
		return "0"
	}
	return v.String()
}

func decodeHexMaybe(v string) ([]byte, error) {
	s := strings.TrimSpace(strings.TrimPrefix(v, "0x"))
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}
