package tsshost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/juno-intents/intents-juno/internal/tss"
)

var ErrInvalidExecSignerConfig = errors.New("tsshost: invalid exec signer config")

type execSignerFn func(ctx context.Context, bin string, args []string, stdin []byte) ([]byte, []byte, error)

type ExecSigner struct {
	bin  string
	args []string

	maxResponseBytes int
	execFn           execSignerFn
}

func NewExecSigner(bin string, args []string, maxResponseBytes int) (*ExecSigner, error) {
	if strings.TrimSpace(bin) == "" {
		return nil, fmt.Errorf("%w: missing signer binary", ErrInvalidExecSignerConfig)
	}
	for i, arg := range args {
		if strings.TrimSpace(arg) == "" {
			return nil, fmt.Errorf("%w: signer arg %d is blank", ErrInvalidExecSignerConfig, i)
		}
	}
	if maxResponseBytes <= 0 {
		return nil, fmt.Errorf("%w: max response bytes must be > 0", ErrInvalidExecSignerConfig)
	}
	return &ExecSigner{
		bin:              bin,
		args:             append([]string(nil), args...),
		maxResponseBytes: maxResponseBytes,
		execFn:           runExecSigner,
	}, nil
}

func (s *ExecSigner) Ready(context.Context) error {
	if s == nil {
		return fmt.Errorf("%w: nil signer", ErrInvalidExecSignerConfig)
	}
	path, err := resolveExecSignerPath(s.bin)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("tsshost: stat signer binary: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("tsshost: signer binary path %q is a directory", path)
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("tsshost: signer binary path %q is not executable", path)
	}
	return nil
}

func (s *ExecSigner) Sign(ctx context.Context, sessionID [32]byte, batchID [32]byte, txPlan []byte) ([]byte, error) {
	if s == nil || s.execFn == nil {
		return nil, fmt.Errorf("%w: nil signer", ErrInvalidExecSignerConfig)
	}
	if len(txPlan) == 0 {
		return nil, fmt.Errorf("%w: empty txplan", ErrInvalidExecSignerConfig)
	}

	req, err := json.Marshal(tss.SignRequest{
		Version:   tss.SignRequestVersion,
		SessionID: tss.FormatSessionID(sessionID),
		BatchID:   tss.FormatBatchID(batchID),
		TxPlan:    txPlan,
	})
	if err != nil {
		return nil, fmt.Errorf("tsshost: marshal signer request: %w", err)
	}

	stdout, stderr, err := s.execFn(ctx, s.bin, s.args, req)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(stdout))
		}
		if msg == "" {
			return nil, fmt.Errorf("tsshost: execute signer: %w", err)
		}
		return nil, fmt.Errorf("tsshost: execute signer: %w: %s", err, msg)
	}
	if len(stdout) > s.maxResponseBytes {
		return nil, fmt.Errorf("tsshost: signer response too large")
	}

	var resp tss.SignResponse
	if err := json.Unmarshal(stdout, &resp); err != nil {
		return nil, fmt.Errorf("tsshost: decode signer response: %w", err)
	}
	if resp.Version != tss.SignResponseVersion {
		return nil, fmt.Errorf("tsshost: unexpected response version %q", resp.Version)
	}
	if resp.SessionID != tss.FormatSessionID(sessionID) {
		return nil, fmt.Errorf("tsshost: response session id mismatch")
	}
	if len(resp.SignedTx) == 0 {
		return nil, fmt.Errorf("tsshost: empty signed tx")
	}
	return resp.SignedTx, nil
}

func resolveExecSignerPath(bin string) (string, error) {
	if strings.TrimSpace(bin) == "" {
		return "", fmt.Errorf("%w: missing signer binary", ErrInvalidExecSignerConfig)
	}
	if strings.ContainsRune(bin, os.PathSeparator) {
		return bin, nil
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return "", fmt.Errorf("tsshost: resolve signer binary: %w", err)
	}
	return path, nil
}

func runExecSigner(ctx context.Context, bin string, args []string, stdin []byte) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}
